package link.aether.client

import android.app.PendingIntent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

/** [VpnFacade] over a real VpnService and its Builder. */
class AndroidVpnFacade(
    private val service: VpnService,
    private val newBuilder: () -> VpnService.Builder,
    private val configureIntent: PendingIntent?,
) : VpnFacade {

    override fun protect(fd: Int): Boolean = service.protect(fd)

    override fun establish(spec: VpnBuilderSpec): TunInterface? {
        val builder = newBuilder()
        val skipped = spec.applyTo(BuilderAdapter(builder), service.packageName)
        // Since Android 10 a VPN is metered by default; ours adds no cost of
        // its own, so let the underlying network decide.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        configureIntent?.let { builder.setConfigureIntent(it) }
        val pfd = builder.establish() ?: return null
        return PfdTun(pfd, skipped)
    }

    private class BuilderAdapter(private val builder: VpnService.Builder) : BuilderSink {
        override fun setSession(session: String) {
            builder.setSession(session)
        }

        override fun setMtu(mtu: Int) {
            builder.setMtu(mtu)
        }

        override fun addAddress(ip: String, prefix: Int) {
            builder.addAddress(ip, prefix)
        }

        override fun addRoute(ip: String, prefix: Int) {
            builder.addRoute(ip, prefix)
        }

        override fun addDnsServer(ip: String) {
            builder.addDnsServer(ip)
        }

        override fun addAllowedApplication(packageName: String): Boolean = try {
            builder.addAllowedApplication(packageName)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }

        override fun addDisallowedApplication(packageName: String): Boolean = try {
            builder.addDisallowedApplication(packageName)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    private class PfdTun(
        private val pfd: ParcelFileDescriptor,
        override val skippedApps: List<String>,
    ) : TunInterface {
        override fun detachFd(): Int = pfd.detachFd()

        override fun close() {
            runCatching { pfd.close() }
        }
    }
}
