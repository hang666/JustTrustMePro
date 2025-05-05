package just.trust.me.pro.hook

import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement

class WebViewHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookWebViewClient(lpparam)
    }

    private fun hookWebViewClient(lpparam: LoadPackageParam) {
        tryHook("WebViewClient.onReceivedSslError") {
            XposedHelpers.findAndHookMethod(
                "android.webkit.WebViewClient",
                lpparam.classLoader,
                "onReceivedSslError",
                WebView::class.java,
                SslErrorHandler::class.java,
                SslError::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        (param.args[1] as SslErrorHandler).proceed()
                        return null
                    }
                }
            )
        }

        tryHook("WebViewClient.onReceivedError") {
            XposedHelpers.findAndHookMethod(
                "android.webkit.WebViewClient",
                lpparam.classLoader,
                "onReceivedError",
                WebView::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
                String::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }
    }
}