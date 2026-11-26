package link.aether.client

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

/**
 * The one screen: connection settings, status, Connect/Disconnect and the
 * entry to the app picker. Built in code (a single LinearLayout), no XML.
 */
class MainActivity : ComponentActivity() {
    private lateinit var store: ConfigStore
    private lateinit var flow: ConnectFlow

    private lateinit var server: EditText
    private lateinit var sni: EditText
    private lateinit var psk: EditText
    private lateinit var ca: EditText
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var apps: Button

    private var unsubscribe: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ConfigStore(this)
        flow = ConnectFlow(this) {
            Toast.makeText(this, R.string.consent_denied, Toast.LENGTH_LONG).show()
        }

        server = field(R.string.hint_server, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        sni = field(R.string.hint_sni, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        psk = field(R.string.hint_psk, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        ca = field(R.string.hint_ca, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE).apply {
            minLines = 2
            maxLines = 6
            gravity = Gravity.TOP or Gravity.START
        }
        status = TextView(this).apply {
            textSize = 16f
            setPadding(0, dp(16), 0, dp(16))
        }
        toggle = Button(this).apply { setOnClickListener { onToggle() } }
        apps = Button(this).apply {
            setOnClickListener { startActivity(Intent(this@MainActivity, AppPickerActivity::class.java)) }
        }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            listOf<View>(server, sni, psk, ca, status, toggle, apps).forEach { addView(it) }
        }
        setContentView(ScrollView(this).apply { addView(column) })

        // Fields are filled only once: a rotation keeps what the user typed.
        if (savedInstanceState == null) {
            val saved = store.load()
            server.setText(saved.server)
            sni.setText(saved.sni)
            psk.setText(saved.psk)
            ca.setText(saved.caPem)
        }
    }

    override fun onStart() {
        super.onStart()
        val selected = store.load().allowedApps.size
        apps.text = if (selected == 0) {
            getString(R.string.apps_all)
        } else {
            getString(R.string.apps_selected, selected)
        }
        unsubscribe = ServiceState.observe { state -> runOnUiThread { render(state) } }
    }

    override fun onStop() {
        unsubscribe?.invoke()
        unsubscribe = null
        save()
        super.onStop()
    }

    private fun onToggle() {
        when (ServiceState.current.phase) {
            Phase.IDLE, Phase.FAILED -> {
                save()
                val problems = ConfigCodec.validate(store.load())
                if (problems.isNotEmpty()) {
                    render(TunnelState(Phase.FAILED, problems.joinToString { describe(it) }))
                    return
                }
                flow.connect()
            }
            else -> flow.disconnect()
        }
    }

    private fun render(state: TunnelState) {
        val phase = when (state.phase) {
            Phase.IDLE -> getString(R.string.state_idle)
            Phase.CONNECTING -> getString(R.string.state_connecting)
            Phase.CONNECTED -> getString(R.string.state_connected)
            Phase.DISCONNECTING -> getString(R.string.state_disconnecting)
            Phase.FAILED -> getString(R.string.state_failed)
        }
        status.text = if (state.detail.isEmpty()) phase else "$phase\n${state.detail}"
        val idle = state.phase == Phase.IDLE || state.phase == Phase.FAILED
        toggle.setText(if (idle) R.string.action_connect else R.string.action_disconnect)
        toggle.isEnabled = state.phase != Phase.DISCONNECTING
        // Editing settings of a live tunnel would silently not apply.
        listOf(server, sni, psk, ca, apps).forEach { it.isEnabled = idle }
    }

    private fun save() {
        store.saveConnection(
            server = server.text.toString().trim(),
            sni = sni.text.toString().trim(),
            psk = psk.text.toString(),
            caPem = ca.text.toString().trim(),
        )
    }

    private fun describe(problem: SettingsProblem): String = getString(
        when (problem) {
            SettingsProblem.SERVER_MISSING -> R.string.problem_server_missing
            SettingsProblem.SERVER_INVALID -> R.string.problem_server_invalid
            SettingsProblem.PSK_MISSING -> R.string.problem_psk_missing
            SettingsProblem.CA_INVALID -> R.string.problem_ca_invalid
        },
    )

    private fun field(hint: Int, type: Int): EditText = EditText(this).apply {
        setHint(hint)
        // inputType alone decides single/multi line; setSingleLine() after a
        // password type would replace the masking transformation.
        inputType = type
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
