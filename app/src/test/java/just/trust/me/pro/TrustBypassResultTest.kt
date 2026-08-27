package just.trust.me.pro

import just.trust.me.pro.util.SSLUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.cert.X509Certificate

class TrustBypassResultTest {
    @Test
    fun voidReturnIsNull() {
        val result = SSLUtils.bypassTrustCheckResult(Void.TYPE, arrayOf<X509Certificate>())
        assertNull(result)
    }

    @Test
    fun listReturnIsListNotArray() {
        val result = SSLUtils.bypassTrustCheckResult(
            MutableList::class.java,
            arrayOf<X509Certificate>()
        )
        assertTrue(result is List<*>)
        assertFalse(result is Array<*>)
        assertEquals(0, (result as List<*>).size)
    }

    @Test
    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    fun javaUtilListMatchesChromiumExpectation() {
        val result = SSLUtils.bypassTrustCheckResult(
            java.util.List::class.java,
            arrayOf<X509Certificate>()
        )
        assertTrue(result is java.util.List<*>)
        (result as java.util.List<*>).size
    }

    @Test
    fun existingCollectionIsCopiedToList() {
        val input = listOf<X509Certificate>()
        val result = SSLUtils.bypassTrustCheckResult(java.util.List::class.java, input)
        assertTrue(result is List<*>)
        assertEquals(0, (result as List<*>).size)
    }
}
