package link.aether.client

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

data class IpPrefix(val ip: String, val prefix: Int)

enum class AppsMode { ALL, ALLOW, DENY }

/** The part of `VpnService.Builder` a plan needs; faked in tests. */
interface BuilderSink {
    fun setSession(session: String)
    fun setMtu(mtu: Int)
    fun addAddress(ip: String, prefix: Int)
    fun addRoute(ip: String, prefix: Int)
    fun addDnsServer(ip: String)

    /** false when the package is not installed (Builder throws NameNotFound). */
    fun addAllowedApplication(packageName: String): Boolean

    /** false when the package is not installed. */
    fun addDisallowedApplication(packageName: String): Boolean
}

/**
 * The interface plan from `clientPlan` (contract: PLAN_ANDROID §4.2). The
 * Rust core decides *what* the tunnel looks like; this only applies it.
 */
data class VpnBuilderSpec(
    val session: String,
    val mtu: Int,
    val address: IpPrefix,
    val dns: List<String>,
    val routes: List<IpPrefix>,
    val appsMode: AppsMode,
    val packages: List<String>,
    val blockIpv6: Boolean,
) {
    /**
     * Apply the plan to [sink]. Exactly one kind of app list is used (Android
     * throws when allowed and disallowed are mixed). Returns the packages that
     * were skipped because they are not installed.
     */
    fun applyTo(sink: BuilderSink, selfPackage: String): List<String> {
        sink.setSession(session)
        sink.setMtu(mtu)
        sink.addAddress(address.ip, address.prefix)
        // Without an IPv6 route, IPv6 would bypass the tunnel on the physical
        // network. The black hole captures it; the core drops non-IPv4.
        if (blockIpv6) sink.addAddress(IPV6_BLACKHOLE_ADDRESS, IPV6_BLACKHOLE_PREFIX)
        dns.forEach { sink.addDnsServer(it) }
        routes.forEach { sink.addRoute(it.ip, it.prefix) }
        if (blockIpv6) sink.addRoute("::", 0)

        val skipped = mutableListOf<String>()
        when (appsMode) {
            AppsMode.ALL -> Unit
            AppsMode.ALLOW -> {
                var added = 0
                for (pkg in packages) {
                    if (sink.addAllowedApplication(pkg)) added++ else skipped += pkg
                }
                // An allow list where nothing could be added would make
                // Android route *every* app into the tunnel. Keep "only these"
                // by allowing just ourselves.
                if (added == 0) sink.addAllowedApplication(selfPackage)
            }
            AppsMode.DENY -> packages.forEach { if (!sink.addDisallowedApplication(it)) skipped += it }
        }
        return skipped
    }

    companion object {
        const val IPV6_BLACKHOLE_ADDRESS = "fd00:1::1"
        const val IPV6_BLACKHOLE_PREFIX = 64

        /** Parse a plan document; [IllegalArgumentException] when it is not one. */
        fun parse(json: String): VpnBuilderSpec = try {
            val root = JSONObject(json)
            val address = root.getJSONObject("address")
            val apps = root.getJSONObject("apps")
            val mode = when (val m = apps.getString("mode")) {
                "all" -> AppsMode.ALL
                "allow" -> AppsMode.ALLOW
                "deny" -> AppsMode.DENY
                else -> throw IllegalArgumentException("unknown apps mode: $m")
            }
            val mtu = root.getInt("mtu")
            require(mtu in 576..65535) { "mtu out of range: $mtu" }
            val routes = root.getJSONArray("routes").objects().map {
                IpPrefix(it.getString("ip"), it.getInt("prefix"))
            }
            require(routes.isNotEmpty()) { "plan has no routes" }
            VpnBuilderSpec(
                session = root.getString("session"),
                mtu = mtu,
                address = IpPrefix(address.getString("ip"), address.getInt("prefix")),
                dns = root.getJSONArray("dns").strings(),
                routes = routes,
                appsMode = mode,
                packages = apps.getJSONArray("packages").strings(),
                blockIpv6 = root.optBoolean("block_ipv6", true),
            )
        } catch (e: JSONException) {
            throw IllegalArgumentException("bad plan JSON: ${e.message}", e)
        }

        private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }

        private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
    }
}
