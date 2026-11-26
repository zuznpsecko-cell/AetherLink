package link.aether.client

import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** P1: settings -> clientCreate JSON, and the private settings store. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ConfigCodecTest {

    private val pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

    @Test
    fun serverGetsTheDefaultPort() {
        assertEquals("vpn.example.com:443", ConfigCodec.normalizeServer(" vpn.example.com "))
        assertEquals("203.0.113.10:8443", ConfigCodec.normalizeServer("203.0.113.10:8443"))
        assertNull(ConfigCodec.normalizeServer("vpn.example.com:70000"))
        assertNull(ConfigCodec.normalizeServer("https://vpn.example.com"))
        assertNull(ConfigCodec.normalizeServer(""))
    }

    @Test
    fun validationNamesEveryProblem() {
        assertEquals(
            listOf(SettingsProblem.SERVER_MISSING, SettingsProblem.PSK_MISSING),
            ConfigCodec.validate(ClientSettings()),
        )
        assertEquals(
            listOf(SettingsProblem.SERVER_INVALID, SettingsProblem.CA_INVALID),
            ConfigCodec.validate(ClientSettings(server = "a b", psk = "k", caPem = "garbage")),
        )
        assertTrue(ConfigCodec.validate(ClientSettings(server = "vpn.example.com", psk = "k")).isEmpty())
    }

    @Test
    fun minimalSettingsBecomeAClientSectionWithSplitAll() {
        val doc = JSONObject(ConfigCodec.toCoreJson(ClientSettings(server = "vpn.example.com", psk = "secret")))
        val client = doc.getJSONObject("client")

        assertEquals("vpn.example.com:443", client.getString("server_addr"))
        assertEquals("secret", client.getString("psk"))
        assertFalse(client.has("outer_sni"))
        assertFalse(client.has("tls"))
        val split = client.getJSONObject("android").getJSONObject("split")
        assertEquals("all", split.getString("mode"))
        assertEquals(0, split.getJSONArray("apps").length())
    }

    @Test
    fun fullSettingsCarrySniCaAndAnAllowList() {
        val settings = ClientSettings(
            server = "203.0.113.10:443",
            sni = "cdn.example.com",
            psk = "secret",
            caPem = pem,
            allowedApps = setOf("org.b", "org.a"),
        )
        val client = JSONObject(ConfigCodec.toCoreJson(settings)).getJSONObject("client")

        assertEquals("cdn.example.com", client.getString("outer_sni"))
        assertEquals(pem, client.getJSONObject("tls").getString("ca_pem"))
        val split = client.getJSONObject("android").getJSONObject("split")
        assertEquals("allow", split.getString("mode"))
        assertEquals("org.a", split.getJSONArray("apps").getString(0))
        assertEquals("org.b", split.getJSONArray("apps").getString(1))
    }

    @Test
    fun settingsNeverPrintThePsk() {
        val text = ClientSettings(server = "s", psk = "hunter2").toString()
        assertFalse(text, text.contains("hunter2"))
    }

    @Test
    fun storeRoundTripsAndKeepsTheAppSelection() {
        val store = ConfigStore(ApplicationProvider.getApplicationContext())
        store.setAllowedApps(setOf("org.a"))
        store.saveConnection("vpn.example.com", "", "secret", pem)

        val loaded = ConfigStore(ApplicationProvider.getApplicationContext()).load()

        assertEquals(
            ClientSettings("vpn.example.com", "", "secret", pem, setOf("org.a")),
            loaded,
        )
    }
}
