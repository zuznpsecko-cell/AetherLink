package link.aether.client

import java.util.concurrent.CopyOnWriteArraySet

enum class Phase { IDLE, CONNECTING, CONNECTED, DISCONNECTING, FAILED }

/** What the UI shows. [detail]: server while connected, reason when failed. */
data class TunnelState(val phase: Phase, val detail: String = "")

/**
 * Process-wide tunnel state: the service publishes, the activities observe.
 * Listeners are called on the publishing thread; UI code marshals to main.
 */
object ServiceState {
    private val listeners = CopyOnWriteArraySet<(TunnelState) -> Unit>()

    @Volatile
    var current: TunnelState = TunnelState(Phase.IDLE)
        private set

    fun update(state: TunnelState) {
        current = state
        listeners.forEach { it(state) }
    }

    /** Subscribe; the listener immediately gets [current]. Returns unsubscribe. */
    fun observe(listener: (TunnelState) -> Unit): () -> Unit {
        listeners += listener
        listener(current)
        return { listeners -= listener }
    }
}
