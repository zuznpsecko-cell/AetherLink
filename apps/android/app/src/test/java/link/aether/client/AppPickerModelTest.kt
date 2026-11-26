package link.aether.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** P4: app picker state (pure JVM). */
class AppPickerModelTest {

    private val apps = listOf(
        AppEntry("Browser", "org.example.browser"),
        AppEntry("bank", "org.example.bank"),
        AppEntry("Browser", "org.example.browser"),
        AppEntry("Maps", "org.example.maps"),
    )

    @Test
    fun listIsDeduplicatedAndSortedByLabel() {
        val model = AppPickerModel(apps, emptySet())

        assertEquals(listOf("bank", "Browser", "Maps"), model.visible().map { it.label })
    }

    @Test
    fun searchMatchesLabelOrPackage() {
        val model = AppPickerModel(apps, emptySet())

        model.query = "MAP"
        assertEquals(listOf("org.example.maps"), model.visible().map { it.packageName })

        model.query = "example.b"
        assertEquals(2, model.visible().size)
    }

    @Test
    fun toggleAndClearDriveTheSelection() {
        val model = AppPickerModel(apps, setOf("org.uninstalled"))

        assertTrue(model.toggle("org.example.maps"))
        assertTrue(model.isSelected("org.example.maps"))
        assertEquals(setOf("org.uninstalled", "org.example.maps"), model.selected)

        assertFalse(model.toggle("org.example.maps"))
        model.clear()
        assertEquals(emptySet<String>(), model.selected)
    }
}
