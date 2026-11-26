// AetherLink Android VpnService (Kotlin).
//
// THIN HOST: VpnService.Builder.establish() -> detached tun fd -> Rust core
// via JNI. Data plane (netstack, crypto, mux, DNS) lives in Rust only; this
// file performs no crypto (no javax.crypto) and parses no frames.

package link.aether.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import org.json.JSONException
import org.json.JSONObject

/**
 * Foreground VPN service. The Intent carries only the action: the config
 * (PSK, CA) is read from [ConfigStore] on the worker thread.
 */
class AetherVpnService : VpnService() {
    // One worker thread: every core call runs here, in order, off main. The
    // TLS handshake inside clientConnect and the pump join inside
    // clientDisconnect can each take seconds.
    private val executor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "aether-vpn") }

    // Touched only on the executor thread.
    private var session: TunnelSession? = null
    private var healthTick: ScheduledFuture<*>? = null

    @Volatile
    private var lastStartId = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        // Started via startForegroundService: Android kills the app unless
        // startForeground runs within seconds, whatever the action is.
        goForeground(getString(R.string.notif_connecting))
        when (intent?.action) {
            ACTION_DISCONNECT -> executor.execute { stopTunnel(TunnelState(Phase.IDLE)) }
            // ACTION_CONNECT, or the system starting an always-on VPN
            // (action android.net.VpnService).
            else -> executor.execute { startTunnel() }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked us in Settings.
        executor.execute { stopTunnel(TunnelState(Phase.IDLE, getString(R.string.state_revoked))) }
    }

    override fun onDestroy() {
        executor.execute {
            // Destroyed with a live tunnel (system or app update): the UI
            // must not keep showing "connected".
            if (session != null) {
                teardown()
                ServiceState.update(TunnelState(Phase.IDLE))
            }
        }
        executor.shutdown()
        super.onDestroy()
    }

    private fun startTunnel() {
        if (session?.isActive == true) return
        ServiceState.update(TunnelState(Phase.CONNECTING))

        val settings = ConfigStore(this).load()
        val problems = ConfigCodec.validate(settings)
        if (problems.isNotEmpty()) {
            stopTunnel(TunnelState(Phase.FAILED, getString(R.string.state_bad_settings, problems.joinToString())))
            return
        }

        val tunnel = TunnelSession(NativeCore, AndroidVpnFacade(this, { Builder() }, openAppIntent()))
        session = tunnel
        val outcome = try {
            tunnel.connect(ConfigCodec.toCoreJson(settings))
        } catch (e: Throwable) {
            // UnsatisfiedLinkError when libaetherlink_core.so is missing for
            // this ABI, or anything unexpected: fail visibly, do not crash.
            runCatching { tunnel.disconnect() }
            ConnectOutcome.Failed("${e.javaClass.simpleName}: ${e.message}")
        }
        when (outcome) {
            is ConnectOutcome.Connected -> {
                // Split default is mode all: every app goes through the tunnel.
                val scope = if (outcome.appsMode == AppsMode.ALL) {
                    getString(R.string.scope_all_apps)
                } else {
                    getString(R.string.scope_some_apps)
                }
                val skipped = if (outcome.skippedApps.isEmpty()) {
                    ""
                } else {
                    "\n" + getString(R.string.skipped_apps, outcome.skippedApps.joinToString())
                }
                val server = ConfigCodec.normalizeServer(settings.server).orEmpty()
                ServiceState.update(TunnelState(Phase.CONNECTED, "$server · $scope$skipped"))
                goForeground(getString(R.string.notif_connected, server))
                healthTick = executor.scheduleWithFixedDelay(
                    { checkHealth() },
                    HEALTH_PERIOD_S,
                    HEALTH_PERIOD_S,
                    TimeUnit.SECONDS,
                )
            }
            is ConnectOutcome.Failed -> {
                session = null
                stopTunnel(TunnelState(Phase.FAILED, outcome.reason))
            }
        }
    }

    private fun checkHealth() {
        val tunnel = session ?: return
        val health = try {
            tunnel.health()
        } catch (e: Throwable) {
            TunnelHealth.Dead("${e.javaClass.simpleName}: ${e.message}")
        }
        if (health is TunnelHealth.Dead) {
            // Routes and DNS still point into the tun: a dead pump would
            // black-hole every app. Tear down instead of showing "connected".
            stopTunnel(TunnelState(Phase.FAILED, getString(R.string.state_tunnel_lost, health.reason)))
        }
    }

    private fun stopTunnel(endState: TunnelState) {
        if (session != null) ServiceState.update(TunnelState(Phase.DISCONNECTING))
        teardown()
        ServiceState.update(endState)
        stopForeground(STOP_FOREGROUND_REMOVE)
        // Only if no newer start arrived meanwhile (e.g. Connect right after
        // Disconnect): that start keeps the service alive.
        stopSelfResult(lastStartId)
    }

    private fun teardown() {
        healthTick?.cancel(false)
        healthTick = null
        val tunnel = session ?: return
        session = null
        runCatching { tunnel.disconnect() }
    }

    private fun goForeground(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW),
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, AetherVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openAppIntent())
            .addAction(
                Notification.Action.Builder(null, getString(R.string.action_disconnect), disconnect).build(),
            )
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    companion object {
        const val ACTION_CONNECT = "link.aether.client.CONNECT"
        const val ACTION_DISCONNECT = "link.aether.client.DISCONNECT"
        private const val CHANNEL_ID = "aetherlink.vpn"
        private const val NOTIFICATION_ID = 1
        private const val HEALTH_PERIOD_S = 2L

        fun connect(context: Context) {
            val intent = Intent(context, AetherVpnService::class.java).setAction(ACTION_CONNECT)
            context.startForegroundService(intent)
        }

        fun disconnect(context: Context) {
            val intent = Intent(context, AetherVpnService::class.java).setAction(ACTION_DISCONNECT)
            context.startForegroundService(intent)
        }
    }
}

sealed class ConnectOutcome {
    /**
     * Tunnel is up. [appsMode]: which apps it carries; [skippedApps]: selected
     * apps that are not installed (Android would throw on them).
     */
    data class Connected(val appsMode: AppsMode, val skippedApps: List<String>) : ConnectOutcome()

    data class Failed(val reason: String) : ConnectOutcome()
}

sealed class TunnelHealth {
    object Alive : TunnelHealth()

    data class Dead(val reason: String) : TunnelHealth()
}

/**
 * The Android connect sequence, as pure orchestration over [CoreApi] and
 * [VpnFacade]. The service runs it on its worker thread, never on main: the
 * TLS handshake inside clientConnect can take seconds.
 *
 * Order: clientCreate -> clientConnect -> clientPlan -> establish ->
 * detachFd -> clientAttachTun.
 *
 * clientConnect runs *before* establish(), unlike the ToyVpn order in
 * PLAN_ANDROID D1: the core resolves the server name and connects while the
 * normal network is still the default (with the VPN up, our own DNS query
 * would go into a tunnel that has no pump yet), and an unreachable server
 * never leaves a half-made interface behind. The transport socket is still
 * protected before it connects, so it keeps bypassing the tunnel afterwards.
 */
class TunnelSession(private val core: CoreApi, private val vpn: VpnFacade) {
    private var handle = 0L

    val isActive: Boolean get() = handle != 0L

    fun connect(configJson: String): ConnectOutcome {
        check(handle == 0L) { "already connected" }

        val created = core.clientCreate(configJson)
        if (created == 0L) {
            return ConnectOutcome.Failed(withDetail("config rejected", core.lastError()))
        }
        handle = created

        val connected = core.clientConnect(created, vpn)
        if (connected != CoreCode.SUCCESS) return abort("connect to server failed", connected)

        val planJson = core.clientPlan(created)
        if (planJson.isEmpty()) return abort("no interface plan", CoreCode.INTERNAL_ERROR)
        val spec = try {
            VpnBuilderSpec.parse(planJson)
        } catch (e: IllegalArgumentException) {
            return abortWith("bad interface plan: ${e.message}")
        }

        val tun = try {
            vpn.establish(spec)
        } catch (e: RuntimeException) {
            // Builder rejects a bad address/route, or the VPN permission is gone.
            return abortWith("VPN interface rejected: ${e.message}")
        } ?: return abortWith("Android refused to create the VPN interface (permission revoked?)")
        val tunFd = try {
            tun.detachFd()
        } catch (e: Exception) {
            tun.close()
            return abortWith("detachFd failed: ${e.message}")
        }

        // From here the fd belongs to the core, even when attach fails (the
        // core closes it): never close it here.
        val attached = core.clientAttachTun(created, tunFd, spec.mtu)
        if (attached != CoreCode.SUCCESS) return abort("attaching the tun failed", attached)

        return ConnectOutcome.Connected(spec.appsMode, tun.skippedApps)
    }

    /** Poll once: is the pump still moving packets? */
    fun health(): TunnelHealth {
        val current = handle
        if (current == 0L) return TunnelHealth.Dead("not connected")
        val text = core.clientStatus(current)
        if (text.isEmpty()) {
            val error = core.lastError()
            // Busy: another call on the handle is in flight; try next tick.
            return if (error.contains("busy", ignoreCase = true)) {
                TunnelHealth.Alive
            } else {
                TunnelHealth.Dead(withDetail("status unavailable", error))
            }
        }
        return try {
            val doc = JSONObject(text)
            if (doc.optBoolean("up") && doc.optBoolean("pump_alive")) {
                TunnelHealth.Alive
            } else {
                val reason = if (doc.isNull("pump_error")) "" else doc.optString("pump_error")
                TunnelHealth.Dead(reason.ifEmpty { "tunnel stopped" })
            }
        } catch (e: JSONException) {
            TunnelHealth.Dead("bad status: ${e.message}")
        }
    }

    /** Stop the pump, close the tun (core side) and release the handle. */
    fun disconnect() {
        val current = handle
        if (current == 0L) return
        handle = 0L
        core.clientDisconnect(current)
        core.clientFree(current)
    }

    private fun abort(what: String, code: Int): ConnectOutcome.Failed {
        // Read the error text before teardown: every core call clears it.
        val detail = core.lastError()
        release()
        return ConnectOutcome.Failed(withDetail("$what: ${CoreCode.name(code)} ($code)", detail))
    }

    private fun abortWith(reason: String): ConnectOutcome.Failed {
        release()
        return ConnectOutcome.Failed(reason)
    }

    private fun release() {
        val current = handle
        handle = 0L
        if (current != 0L) {
            core.clientDisconnect(current)
            core.clientFree(current)
        }
    }

    private fun withDetail(what: String, detail: String): String =
        if (detail.isBlank()) what else "$what: $detail"
}
