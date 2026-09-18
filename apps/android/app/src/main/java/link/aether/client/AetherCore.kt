// AetherLink JNI bridge (Kotlin).
//
// THIN BRIDGE: loads aetherlink_core and forwards lifecycle calls.
// No crypto, no framing, no sockets here (no javax.crypto).

package link.aether.client

object AetherCore {
    init {
        // Rust core: per-ABI .so (arm64-v8a, armeabi-v7a, x86_64).
        System.loadLibrary("aetherlink_core")
    }

    external fun clientCreate(configJson: String): Long
    external fun clientUp(handle: Long): Int
    external fun clientDown(handle: Long): Int
    external fun setTunFd(handle: Long, fd: Int, mtu: Int): Int
    external fun setSplitConfig(handle: Long, configJson: String): Int
    external fun forceCleanup(): Int
}
