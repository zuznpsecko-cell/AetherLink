package link.aether.client

import org.json.JSONArray
import org.json.JSONObject

/** What the user entered on the main screen plus the app picker selection. */
data class ClientSettings(
    val server: String = "",
    val sni: String = "",
    val psk: String = "",
    val caPem: String = "",
    /** Empty = every app goes through the tunnel; otherwise only these. */
    val allowedApps: Set<String> = emptySet(),
) {
    // The PSK must never reach logs, crash reports or debugger dumps.
    override fun toString(): String =
        "ClientSettings(server=$server, sni=$sni, psk=${if (psk.isEmpty()) "" else "***"}, " +
            "caPem=${caPem.length} chars, allowedApps=$allowedApps)"
}

enum class SettingsProblem { SERVER_MISSING, SERVER_INVALID, PSK_MISSING, CA_INVALID }

/**
 * Settings -> the JSON document `clientCreate` accepts (the §8 client
 * schema). Validation here only catches typos early; the core validates the
 * document again and stays the authority.
 */
object ConfigCodec {
    const val DEFAULT_PORT = 443

    private val HOST_PORT = Regex("""^([A-Za-z0-9.\-]+):(\d{1,5})$""")
    private val HOST_ONLY = Regex("""^[A-Za-z0-9.\-]+$""")
    private const val CERT_BEGIN = "-----BEGIN CERTIFICATE-----"

    /** `host[:port]` -> `host:port` (port 443 by default); null if malformed. */
    fun normalizeServer(raw: String): String? {
        val text = raw.trim()
        if (text.isEmpty()) return null
        val match = HOST_PORT.matchEntire(text)
        if (match != null) {
            val port = match.groupValues[2].toInt()
            return if (port in 1..65535) text else null
        }
        return if (HOST_ONLY.matches(text)) "$text:$DEFAULT_PORT" else null
    }

    fun validate(settings: ClientSettings): List<SettingsProblem> {
        val problems = mutableListOf<SettingsProblem>()
        when {
            settings.server.isBlank() -> problems += SettingsProblem.SERVER_MISSING
            normalizeServer(settings.server) == null -> problems += SettingsProblem.SERVER_INVALID
        }
        if (settings.psk.isEmpty()) problems += SettingsProblem.PSK_MISSING
        if (settings.caPem.isNotBlank() && !settings.caPem.contains(CERT_BEGIN)) {
            problems += SettingsProblem.CA_INVALID
        }
        return problems
    }

    /** The `clientCreate` document. Call [validate] first. */
    fun toCoreJson(settings: ClientSettings): String {
        val server = requireNotNull(normalizeServer(settings.server)) { "server address is invalid" }
        require(settings.psk.isNotEmpty()) { "psk is empty" }

        val client = JSONObject()
            .put("server_addr", server)
            .put("psk", settings.psk)
        val sni = settings.sni.trim()
        if (sni.isNotEmpty()) client.put("outer_sni", sni)
        val ca = settings.caPem.trim()
        if (ca.isNotEmpty()) client.put("tls", JSONObject().put("ca_pem", ca))

        // Split default: mode "all" (every app). A selection means "only these".
        val apps = settings.allowedApps.filter { it.isNotBlank() }.sorted()
        val split = JSONObject()
            .put("mode", if (apps.isEmpty()) "all" else "allow")
            .put("apps", JSONArray(apps))
        client.put("android", JSONObject().put("split", split))

        return JSONObject().put("client", client).toString()
    }
}
