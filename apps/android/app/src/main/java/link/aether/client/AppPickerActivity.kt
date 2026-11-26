package link.aether.client

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import androidx.activity.ComponentActivity

/**
 * One list of launchable apps with checkboxes and a search box. Nothing
 * checked = every app goes through the tunnel; otherwise only the checked
 * ones. Every toggle is saved at once and applies on the next connect.
 */
class AppPickerActivity : ComponentActivity() {
    private lateinit var store: ConfigStore
    private lateinit var summary: TextView
    private val adapter = AppsAdapter()
    private var model = AppPickerModel(emptyList(), emptySet())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ConfigStore(this)
        model = AppPickerModel(emptyList(), store.load().allowedApps)

        val pad = (16 * resources.displayMetrics.density).toInt()
        summary = TextView(this).apply { setPadding(0, 0, 0, pad / 2) }
        val search = EditText(this).apply {
            setHint(R.string.hint_search)
            inputType = InputType.TYPE_CLASS_TEXT
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
                override fun afterTextChanged(s: Editable?) {
                    model.query = s?.toString().orEmpty()
                    adapter.notifyDataSetChanged()
                }
            })
        }
        val all = Button(this).apply {
            setText(R.string.apps_reset)
            setOnClickListener {
                model.clear()
                persist()
            }
        }
        val list = ListView(this).apply {
            adapter = this@AppPickerActivity.adapter
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(pad, pad, pad, 0)
                addView(summary)
                addView(search)
                addView(all)
                addView(list)
            },
        )
        renderSummary()
        loadApps()
    }

    private fun loadApps() {
        summary.setText(R.string.apps_loading)
        // Labels come from every app's resources: slow, keep it off main.
        Thread({
            val pm = packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val entries = pm.queryIntentActivities(launcher, 0)
                .map { it.activityInfo.applicationInfo }
                .filter { it.packageName != packageName }
                .map { AppEntry(it.loadLabel(pm).toString(), it.packageName) }
            runOnUiThread {
                if (isDestroyed) return@runOnUiThread
                model = AppPickerModel(entries, model.selected).also { it.query = model.query }
                adapter.notifyDataSetChanged()
                renderSummary()
            }
        }, "app-list").start()
    }

    private fun persist() {
        store.setAllowedApps(model.selected)
        adapter.notifyDataSetChanged()
        renderSummary()
    }

    private fun renderSummary() {
        val count = model.selected.size
        summary.text = if (count == 0) getString(R.string.apps_all_hint) else getString(R.string.apps_selected, count)
    }

    private inner class AppsAdapter : BaseAdapter() {
        private var rows: List<AppEntry> = emptyList()

        override fun notifyDataSetChanged() {
            rows = model.visible()
            super.notifyDataSetChanged()
        }

        override fun getCount(): Int = rows.size

        override fun getItem(position: Int): AppEntry = rows[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val box = convertView as? CheckBox ?: CheckBox(this@AppPickerActivity)
            val entry = rows[position]
            box.text = getString(R.string.app_row, entry.label, entry.packageName)
            // Detach the listener before setting state: rows are recycled.
            box.setOnCheckedChangeListener(null)
            box.isChecked = model.isSelected(entry.packageName)
            box.setOnCheckedChangeListener { _, _ ->
                model.toggle(entry.packageName)
                persist()
            }
            return box
        }
    }
}
