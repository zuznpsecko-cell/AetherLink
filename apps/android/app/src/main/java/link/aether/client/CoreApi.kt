package link.aether.client

/** `VpnService.protect(fd)`: keep one socket out of our own tunnel. */
fun interface SocketProtector {
    fun protect(fd: Int): Boolean
}

/**
 * The native core as the host sees it: the JNI surface of [AetherCore], with
 * the protector passed explicitly. L1 tests replace it with a fake.
 */
interface CoreApi {
    fun clientCreate(configJson: String): Long
    fun clientPlan(handle: Long): String
    fun clientConnect(handle: Long, protector: SocketProtector): Int
    fun clientAttachTun(handle: Long, fd: Int, mtu: Int): Int
    fun clientStatus(handle: Long): String
    fun clientDisconnect(handle: Long): Int
    fun clientFree(handle: Long): Int
    fun lastError(): String
}

/** Production [CoreApi]: forwards to the JNI object. */
object NativeCore : CoreApi {
    // AetherCore.protector is a single slot: two concurrent connects would
    // see each other's VpnService. One service, one connect at a time.
    private val connectLock = Any()

    override fun clientCreate(configJson: String): Long = AetherCore.clientCreate(configJson)

    override fun clientPlan(handle: Long): String = AetherCore.clientPlan(handle).orEmpty()

    override fun clientConnect(handle: Long, protector: SocketProtector): Int =
        synchronized(connectLock) {
            AetherCore.protector = protector
            try {
                AetherCore.clientConnect(handle)
            } finally {
                AetherCore.protector = null
            }
        }

    override fun clientAttachTun(handle: Long, fd: Int, mtu: Int): Int =
        AetherCore.clientAttachTun(handle, fd, mtu)

    override fun clientStatus(handle: Long): String = AetherCore.clientStatus(handle).orEmpty()

    override fun clientDisconnect(handle: Long): Int = AetherCore.clientDisconnect(handle)

    override fun clientFree(handle: Long): Int = AetherCore.clientFree(handle)

    override fun lastError(): String = AetherCore.lastError().orEmpty()
}

/** `AetherError` codes (crates/aetherlink-ffi/src/lib.rs). */
object CoreCode {
    const val SUCCESS = 0
    const val INVALID_HANDLE = -1
    const val INVALID_CONFIG = -2
    const val ALREADY_RUNNING = -3
    const val NOT_RUNNING = -4
    const val NETWORK_ERROR = -5
    const val DNS_ERROR = -6
    const val AUTH_ERROR = -7
    const val INTERNAL_ERROR = -8
    const val INVALID_ARGUMENT = -9
    const val PERMISSION_DENIED = -10
    const val STALE_STATE = -11
    const val BUSY = -12

    fun name(code: Int): String = when (code) {
        SUCCESS -> "Success"
        INVALID_HANDLE -> "InvalidHandle"
        INVALID_CONFIG -> "InvalidConfig"
        ALREADY_RUNNING -> "AlreadyRunning"
        NOT_RUNNING -> "NotRunning"
        NETWORK_ERROR -> "NetworkError"
        DNS_ERROR -> "DnsError"
        AUTH_ERROR -> "AuthError"
        INTERNAL_ERROR -> "InternalError"
        INVALID_ARGUMENT -> "InvalidArgument"
        PERMISSION_DENIED -> "PermissionDenied"
        STALE_STATE -> "StaleState"
        BUSY -> "Busy"
        else -> "Error"
    }
}
