package link.aether.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * P2/P3: the connect sequence in [TunnelSession] against a fake core and a
 * fake VpnService. Robolectric only provides a real org.json.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ServiceOrchestrationTest {

    private val plan = """
        {"session":"AetherLink","mtu":1400,
         "address":{"ip":"10.255.0.2","prefix":30},
         "dns":["10.255.0.1"],
         "routes":[{"ip":"0.0.0.0","prefix":0},{"ip":"10.255.0.1","prefix":32}],
         "apps":{"mode":"all","packages":[]},
         "block_ipv6":true}
    """.trimIndent()

    private class FakeCore(private val plan: String) : CoreApi {
        val calls = mutableListOf<String>()
        var createResult = 7L
        var connectResult = CoreCode.SUCCESS
        var attachResult = CoreCode.SUCCESS
        var planResult: String? = null
        var statusResult = """{"up":true,"pump_alive":true,"pump_error":null}"""
        var error = ""
        var protectedOk: Boolean? = null
        var attachedFd = -1

        override fun clientCreate(configJson: String): Long {
            calls += "create"
            return createResult
        }

        override fun clientPlan(handle: Long): String {
            calls += "plan"
            return planResult ?: plan
        }

        override fun clientConnect(handle: Long, protector: SocketProtector): Int {
            calls += "connect"
            // The core protects its socket before it connects.
            protectedOk = protector.protect(99)
            return connectResult
        }

        override fun clientAttachTun(handle: Long, fd: Int, mtu: Int): Int {
            calls += "attach($fd,$mtu)"
            attachedFd = fd
            return attachResult
        }

        override fun clientStatus(handle: Long): String {
            calls += "status"
            return statusResult
        }

        override fun clientDisconnect(handle: Long): Int {
            calls += "disconnect"
            return CoreCode.SUCCESS
        }

        override fun clientFree(handle: Long): Int {
            calls += "free"
            return CoreCode.SUCCESS
        }

        override fun lastError(): String = error
    }

    private class FakeTun(private val fd: Int, private val calls: MutableList<String>) : TunInterface {
        override val skippedApps: List<String> = emptyList()
        var closed = false

        override fun detachFd(): Int {
            calls += "detach"
            return fd
        }

        override fun close() {
            calls += "close"
            closed = true
        }
    }

    private class FakeVpn(private val calls: MutableList<String>) : VpnFacade {
        val protectedFds = mutableListOf<Int>()
        var refuse = false
        var tun: FakeTun? = null
        var spec: VpnBuilderSpec? = null

        override fun protect(fd: Int): Boolean {
            protectedFds += fd
            return true
        }

        override fun establish(spec: VpnBuilderSpec): TunInterface? {
            calls += "establish"
            this.spec = spec
            if (refuse) return null
            return FakeTun(42, calls).also { tun = it }
        }
    }

    private fun setup(): Triple<FakeCore, FakeVpn, TunnelSession> {
        val core = FakeCore(plan)
        val vpn = FakeVpn(core.calls)
        return Triple(core, vpn, TunnelSession(core, vpn))
    }

    @Test
    fun connectRunsTheSequenceInOrderAndHandsTheDetachedFdToTheCore() {
        val (core, vpn, session) = setup()

        val outcome = session.connect("{}")

        assertEquals(ConnectOutcome.Connected(AppsMode.ALL, emptyList()), outcome)
        assertEquals(listOf("create", "connect", "plan", "establish", "detach", "attach(42,1400)"), core.calls)
        assertEquals(listOf(99), vpn.protectedFds)
        assertEquals(true, core.protectedOk)
        assertEquals(42, core.attachedFd)
        assertTrue(session.isActive)
    }

    @Test
    fun rejectedConfigReportsTheCoreErrorAndCreatesNothing() {
        val (core, _, session) = setup()
        core.createResult = 0L
        core.error = "clientCreate: psk is required"

        val outcome = session.connect("{}")

        assertEquals(ConnectOutcome.Failed("config rejected: clientCreate: psk is required"), outcome)
        assertEquals(listOf("create"), core.calls)
        assertFalse(session.isActive)
    }

    @Test
    fun failedConnectFreesTheHandleAndNeverEstablishesAnInterface() {
        val (core, _, session) = setup()
        core.connectResult = CoreCode.NETWORK_ERROR
        core.error = "clientConnect: connection refused"

        val outcome = session.connect("{}") as ConnectOutcome.Failed

        assertTrue(outcome.reason, outcome.reason.contains("NetworkError"))
        assertTrue(outcome.reason, outcome.reason.contains("connection refused"))
        assertEquals(listOf("create", "connect", "disconnect", "free"), core.calls)
        assertFalse(session.isActive)
    }

    @Test
    fun refusedEstablishReleasesTheCoreHandle() {
        val (core, vpn, session) = setup()
        vpn.refuse = true

        val outcome = session.connect("{}")

        assertTrue(outcome is ConnectOutcome.Failed)
        assertEquals(listOf("create", "connect", "plan", "establish", "disconnect", "free"), core.calls)
    }

    @Test
    fun badPlanNeverReachesTheBuilder() {
        val (core, vpn, session) = setup()
        core.planResult = """{"session":"x"}"""

        val outcome = session.connect("{}")

        assertTrue(outcome is ConnectOutcome.Failed)
        assertEquals(null, vpn.spec)
        assertEquals(listOf("create", "connect", "plan", "disconnect", "free"), core.calls)
    }

    @Test
    fun failedAttachDoesNotCloseTheFdItAlreadyGaveAway() {
        val (core, vpn, session) = setup()
        core.attachResult = CoreCode.INVALID_ARGUMENT

        val outcome = session.connect("{}")

        assertTrue(outcome is ConnectOutcome.Failed)
        // D2: after detachFd the fd belongs to the core, even on failure.
        assertFalse(vpn.tun!!.closed)
        assertEquals(
            listOf("create", "connect", "plan", "establish", "detach", "attach(42,1400)", "disconnect", "free"),
            core.calls,
        )
    }

    @Test
    fun healthFollowsThePump() {
        val (core, _, session) = setup()
        session.connect("{}")

        assertEquals(TunnelHealth.Alive, session.health())

        core.statusResult = """{"up":true,"pump_alive":false,"pump_error":"tun read: EBADF"}"""
        assertEquals(TunnelHealth.Dead("tun read: EBADF"), session.health())
    }

    @Test
    fun busyStatusIsNotADeadTunnel() {
        val (core, _, session) = setup()
        session.connect("{}")
        core.statusResult = ""
        core.error = "clientStatus: client handle is busy with another call, retry"

        assertEquals(TunnelHealth.Alive, session.health())
    }

    @Test
    fun disconnectReleasesOnceAndIsIdempotent() {
        val (core, _, session) = setup()
        session.connect("{}")
        core.calls.clear()

        session.disconnect()
        session.disconnect()

        assertEquals(listOf("disconnect", "free"), core.calls)
        assertFalse(session.isActive)
    }
}
