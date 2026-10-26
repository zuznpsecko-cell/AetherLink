package link.aether.client

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * P0-R2 harness smoke: proves that the JVM test harness (JUnit 4 + Robolectric
 * with Android resources) is wired. Every L1 test in later phases relies on it,
 * so this is the gate that the harness itself works — not the app.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class HarnessSmokeTest {

    @Test
    fun robolectricProvidesTheApplicationContext() {
        val app = RuntimeEnvironment.getApplication()

        assertNotNull("Robolectric must provide an Application", app)
        assertEquals("link.aether.client", app.packageName)

        val fromProvider = ApplicationProvider.getApplicationContext<Context>()
        assertEquals(app, fromProvider)
    }
}
