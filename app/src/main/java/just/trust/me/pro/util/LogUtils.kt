package just.trust.me.pro.util

import android.util.Log

object LogUtils {
    private const val TAG = "JustTrustMePro"

    fun debug(message: String) {
        Log.d(TAG, message)
    }

    fun info(message: String) {
        Log.i(TAG, message)
    }

    fun warn(message: String) {
        Log.w(TAG, message)
    }

    fun error(message: String) {
        Log.e(TAG, message)
    }

    fun hook(name: String, success: Boolean, error: Throwable? = null) {
        val status = if (success) "✓" else "✗"
        val message = buildString {
            append("$status Hook: $name")
            if (!success && error != null) {
                append(" - Error: ${error.message}")
            }
        }
        if (success) {
            debug(message)
        } else {
            warn(message)
        }
    }
}