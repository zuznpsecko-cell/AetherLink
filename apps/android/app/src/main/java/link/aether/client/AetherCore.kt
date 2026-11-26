// AetherLink JNI bridge (Kotlin).
//
// THIN BRIDGE: loads aetherlink_core and forwards calls. No crypto, no
// framing, no sockets here (no javax.crypto). The only call back into Kotlin
// is protectFd: the core invokes it from inside clientConnect, on the same
// thread, right before it connects the transport socket.

package link.aether.client

object AetherCore {
    init {
        // Rust core: per-ABI .so (arm64-v8a, armeabi-v7a, x86_64).
        System.loadLibrary("aetherlink_core")
    }

    /** Set by [NativeCore.clientConnect] for the duration of the call. */
    @Volatile
    internal var protector: SocketProtector? = null

    /**
     * Called from Rust (JNI signature `(I)Z`) on the transport socket before
     * it connects. `false` (no running VpnService) makes the core refuse the
     * connection instead of sending the server's SYN into our own tunnel.
     */
    fun protectFd(fd: Int): Boolean = protector?.protect(fd) ?: false

    /** Validate the JSON config and create a client; 0 on error. */
    external fun clientCreate(configJson: String): Long

    /** VpnService.Builder plan as JSON; "" (or null) on error. */
    external fun clientPlan(handle: Long): String?

    /** Resolve + protect + TCP + TLS + AUTH. */
    external fun clientConnect(handle: Long): Int

    /** Hand the detached tun fd to the core (ownership moves to Rust). */
    external fun clientAttachTun(handle: Long, fd: Int, mtu: Int): Int

    /** Status JSON (`up`, `pump_alive`, `pump_error`, ...); "" on error. */
    external fun clientStatus(handle: Long): String?

    /** Stop the pump and drop the transport (closes the tun fd). */
    external fun clientDisconnect(handle: Long): Int

    /** Release the handle; idempotent. */
    external fun clientFree(handle: Long): Int

    /** Text of the most recent failure; "" when nothing failed. */
    external fun lastError(): String?
}
