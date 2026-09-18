// AetherLink Android VpnService (Kotlin).
//
// THIN UI: VpnService.Builder.establish() -> tun fd -> Rust core via JNI.
// Data plane (netstack, crypto, mux, DNS) lives in Rust only; this file
// performs no crypto (no javax.crypto) and parses no frames.

package link.aether.client

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

class AetherVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Split-tunnel default: MODE_ALL (every app through the tunnel).
        val modeAll = intent?.getBooleanExtra(EXTRA_MODE_ALL, true) ?: true
        val mtu = intent?.getIntExtra(EXTRA_MTU, 1400) ?: 1400

        val builder = Builder()
            .setSession("AetherLink")
            .setMtu(mtu)
            .addAddress("10.255.0.2", 30)
            .addRoute("0.0.0.0", 0)
            // DNS_NO_LEAK: system resolvers point at the virtual DNS gateway.
            .addDnsServer("10.255.0.1")

        if (modeAll) {
            // MODE_ALL: no allow/deny lists; every app goes through the tunnel.
        } else {
            for (pkg in intent?.getStringArrayExtra(EXTRA_ALLOW).orEmpty()) {
                builder.addAllowedApplication(pkg)
            }
            for (pkg in intent?.getStringArrayExtra(EXTRA_DENY).orEmpty()) {
                builder.addDisallowedApplication(pkg)
            }
        }

        tun = builder.establish()
        val fd = tun?.fd ?: -1
        if (fd < 0) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Hand the tun fd to the Rust core; from here the data plane is Rust.
        AetherCore.setTunFd(handle(), fd, mtu)
        AetherCore.clientUp(handle())
        return START_STICKY
    }

    override fun onDestroy() {
        runCatching { AetherCore.clientDown(handle()) }
        runCatching { tun?.close() }
        tun = null
        super.onDestroy()
    }

    private fun handle(): Long = 0L // replaced by real handle from clientCreate

    companion object {
        const val EXTRA_MODE_ALL = "link.aether.MODE_ALL"
        const val EXTRA_MTU = "link.aether.MTU"
        const val EXTRA_ALLOW = "link.aether.ALLOW"
        const val EXTRA_DENY = "link.aether.DENY"
    }
}
