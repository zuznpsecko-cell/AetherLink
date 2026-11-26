package link.aether.client

/** An established VPN interface whose fd has not been handed over yet. */
interface TunInterface {
    /** Selected apps that could not be added because they are not installed. */
    val skippedApps: List<String>

    /** `ParcelFileDescriptor.detachFd()`: the caller owns the fd from now on. */
    fun detachFd(): Int

    /** Close an interface that was never detached. */
    fun close()
}

/** What [ConnectFlow] needs from the VpnService; faked in tests. */
interface VpnFacade : SocketProtector {
    /** Build and establish the interface; null when Android refuses it. */
    fun establish(spec: VpnBuilderSpec): TunInterface?
}
