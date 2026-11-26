package link.aether.client

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

/**
 * UI side of connecting: notification permission (Android 13+, so the
 * foreground notification is visible), the VPN consent dialog from
 * `VpnService.prepare()`, then the foreground service. Construct it while
 * the activity is being created (it registers activity-result callbacks).
 */
class ConnectFlow(
    private val activity: ComponentActivity,
    private val onConsentDenied: () -> Unit,
) {
    private val vpnConsent = activity.registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) AetherVpnService.connect(activity) else onConsentDenied()
    }

    // The tunnel works without the notification; asked once, then proceed.
    private val notificationPermission = activity.registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { requestVpnConsent() }

    fun connect() {
        val needsNotificationPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        if (needsNotificationPermission) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnConsent()
        }
    }

    fun disconnect() {
        when (ServiceState.current.phase) {
            // Nothing running: just clear a stale failure message.
            Phase.IDLE, Phase.FAILED -> ServiceState.update(TunnelState(Phase.IDLE))
            else -> AetherVpnService.disconnect(activity)
        }
    }

    private fun requestVpnConsent() {
        // null: already consented (or we are the always-on VPN).
        val consent = VpnService.prepare(activity)
        if (consent == null) AetherVpnService.connect(activity) else vpnConsent.launch(consent)
    }
}
