package link.aether.client

import android.content.Context

/**
 * Settings in app-private SharedPreferences. The PSK is stored in private
 * mode but not encrypted at rest (same as the desktop YAML); the manifest
 * disables backup so it does not leave the device. The service reads the
 * config from here: no PSK travels through Intent extras.
 */
class ConfigStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun load(): ClientSettings = ClientSettings(
        server = prefs.getString(KEY_SERVER, "").orEmpty(),
        sni = prefs.getString(KEY_SNI, "").orEmpty(),
        psk = prefs.getString(KEY_PSK, "").orEmpty(),
        caPem = prefs.getString(KEY_CA, "").orEmpty(),
        allowedApps = prefs.getStringSet(KEY_APPS, emptySet()).orEmpty().toSet(),
    )

    /** Save the main-screen fields; keeps the app selection. */
    fun saveConnection(server: String, sni: String, psk: String, caPem: String) {
        prefs.edit()
            .putString(KEY_SERVER, server)
            .putString(KEY_SNI, sni)
            .putString(KEY_PSK, psk)
            .putString(KEY_CA, caPem)
            .apply()
    }

    /** Save the app picker selection (empty = all apps). */
    fun setAllowedApps(apps: Set<String>) {
        // A fresh set: SharedPreferences must not keep a reference we mutate.
        prefs.edit().putStringSet(KEY_APPS, HashSet(apps)).apply()
    }

    private companion object {
        const val FILE = "aetherlink.config"
        const val KEY_SERVER = "server"
        const val KEY_SNI = "sni"
        const val KEY_PSK = "psk"
        const val KEY_CA = "ca_pem"
        const val KEY_APPS = "allowed_apps"
    }
}
