package link.aether.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** P4: the plan from clientPlan applied to VpnService.Builder (D4). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VpnBuilderSpecTest {

    private class RecordingSink(private val installed: Set<String>) : BuilderSink {
        val calls = mutableListOf<String>()

        override fun setSession(session: String) {
            calls += "session $session"
        }

        override fun setMtu(mtu: Int) {
            calls += "mtu $mtu"
        }

        override fun addAddress(ip: String, prefix: Int) {
            calls += "address $ip/$prefix"
        }

        override fun addRoute(ip: String, prefix: Int) {
            calls += "route $ip/$prefix"
        }

        override fun addDnsServer(ip: String) {
            calls += "dns $ip"
        }

        override fun addAllowedApplication(packageName: String): Boolean {
            if (packageName !in installed) return false
            calls += "allow $packageName"
            return true
        }

        override fun addDisallowedApplication(packageName: String): Boolean {
            if (packageName !in installed) return false
            calls += "deny $packageName"
            return true
        }
    }

    private fun plan(mode: String, packages: String = "") = """
        {"session":"AetherLink","mtu":1400,
         "address":{"ip":"10.255.0.2","prefix":30},
         "dns":["10.255.0.1"],
         "routes":[{"ip":"0.0.0.0","prefix":0},{"ip":"10.255.0.1","prefix":32}],
         "apps":{"mode":"$mode","packages":[$packages]},
         "block_ipv6":true}
    """.trimIndent()

    @Test
    fun allModeRoutesEverythingAndBlackHolesIpv6() {
        val sink = RecordingSink(emptySet())

        val skipped = VpnBuilderSpec.parse(plan("all")).applyTo(sink, "link.aether.client")

        assertEquals(emptyList<String>(), skipped)
        assertEquals(
            listOf(
                "session AetherLink",
                "mtu 1400",
                "address 10.255.0.2/30",
                "address fd00:1::1/64",
                "dns 10.255.0.1",
                "route 0.0.0.0/0",
                "route 10.255.0.1/32",
                "route ::/0",
            ),
            sink.calls,
        )
    }

    @Test
    fun allowModeSkipsMissingPackages() {
        val sink = RecordingSink(setOf("org.example.browser"))
        val spec = VpnBuilderSpec.parse(plan("allow", "\"org.example.browser\",\"org.gone\""))

        val skipped = spec.applyTo(sink, "link.aether.client")

        assertEquals(listOf("org.gone"), skipped)
        assertTrue(sink.calls.contains("allow org.example.browser"))
        assertTrue(sink.calls.none { it.startsWith("deny") })
    }

    @Test
    fun allowListWithNothingInstalledDoesNotWidenToEveryApp() {
        val sink = RecordingSink(setOf("link.aether.client"))
        val spec = VpnBuilderSpec.parse(plan("allow", "\"org.gone\""))

        spec.applyTo(sink, "link.aether.client")

        assertEquals(listOf("allow link.aether.client"), sink.calls.filter { it.startsWith("allow") })
    }

    @Test
    fun denyModeUsesOnlyTheDisallowedList() {
        val sink = RecordingSink(setOf("org.example.bank"))

        VpnBuilderSpec.parse(plan("deny", "\"org.example.bank\"")).applyTo(sink, "link.aether.client")

        assertTrue(sink.calls.contains("deny org.example.bank"))
        assertTrue(sink.calls.none { it.startsWith("allow") })
    }

    @Test
    fun malformedPlansAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { VpnBuilderSpec.parse("not json") }
        assertThrows(IllegalArgumentException::class.java) { VpnBuilderSpec.parse(plan("subnets")) }
        assertThrows(IllegalArgumentException::class.java) {
            VpnBuilderSpec.parse(plan("all").replace("\"mtu\":1400", "\"mtu\":10"))
        }
    }
}
