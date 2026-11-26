package link.aether.client

data class AppEntry(val label: String, val packageName: String)

/**
 * App picker state: installed launchable apps, the current search and the
 * selection. Empty selection = every app goes through the tunnel; otherwise
 * only the selected ones (`android.split.mode: allow`).
 */
class AppPickerModel(apps: List<AppEntry>, selected: Set<String>) {
    private val all: List<AppEntry> = apps
        .distinctBy { it.packageName }
        .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { entry: AppEntry -> entry.label }.thenBy { it.packageName })

    // Kept even for apps that are no longer installed: the selection is the
    // user's, and the core skips missing packages at connect time.
    private val chosen = selected.toMutableSet()

    var query: String = ""

    val selected: Set<String> get() = chosen.toSet()

    fun isSelected(packageName: String): Boolean = packageName in chosen

    /** Flip one app; returns the new state. */
    fun toggle(packageName: String): Boolean =
        if (chosen.remove(packageName)) {
            false
        } else {
            chosen.add(packageName)
            true
        }

    fun clear() {
        chosen.clear()
    }

    /** Apps matching [query] by label or package name, sorted by label. */
    fun visible(): List<AppEntry> {
        val q = query.trim()
        if (q.isEmpty()) return all
        return all.filter { it.label.contains(q, ignoreCase = true) || it.packageName.contains(q, ignoreCase = true) }
    }
}
