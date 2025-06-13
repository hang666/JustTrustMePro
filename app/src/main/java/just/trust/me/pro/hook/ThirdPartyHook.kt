package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XC_MethodHook
import just.trust.me.pro.util.SSLUtils
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

class ThirdPartyHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookX509TrustManagerExtensions(lpparam)
        hookXUtils(lpparam)
        hookHttpClientAndroidLib(lpparam)
        hookX5SystemWebViewClientError(lpparam)
        hookX5WebViewClientSslError(lpparam)
    }

    private fun hookX5SystemWebViewClientError(lpparam: LoadPackageParam) {
        val hasSystemWebViewClient =
            isClassExists("com.tencent.smtt.sdk.SystemWebViewClient", lpparam)
        val hasAndroidWebView = isClassExists("android.webkit.WebView", lpparam)
        if (hasSystemWebViewClient && hasAndroidWebView) {
            tryHook("X5SystemWebViewClient.onReceivedError(android.webkit.WebView,int,String,String)") {
                XposedHelpers.findAndHookMethod(
                    "com.tencent.smtt.sdk.SystemWebViewClient",
                    lpparam.classLoader,
                    "onReceivedError",
                    lpparam.classLoader.loadClass("android.webkit.WebView"),
                    Int::class.javaPrimitiveType,
                    String::class.java,
                    String::class.java,
                    object : XC_MethodReplacement() {
                        override fun replaceHookedMethod(param: MethodHookParam): Any? {
                            val handler = param.args[1]
                            handler.javaClass.getMethod("proceed").invoke(handler)
                            return null
                        }
                    }
                )
            }

            val hasWebResourceRequest = isClassExists("android.webkit.WebResourceRequest", lpparam)
            val hasWebResourceError = isClassExists("android.webkit.WebResourceError", lpparam)
            if (hasWebResourceRequest && hasWebResourceError) {
                tryHook("X5SystemWebViewClient.onReceivedError(android.webkit.WebView,WebResourceRequest,WebResourceError)") {
                    XposedHelpers.findAndHookMethod(
                        "com.tencent.smtt.sdk.SystemWebViewClient",
                        lpparam.classLoader,
                        "onReceivedError",
                        lpparam.classLoader.loadClass("android.webkit.WebView"),
                        lpparam.classLoader.loadClass("android.webkit.WebResourceRequest"),
                        lpparam.classLoader.loadClass("android.webkit.WebResourceError"),
                        object : XC_MethodReplacement() {
                            override fun replaceHookedMethod(param: MethodHookParam): Any? {
                                val handler = param.args[1]
                                handler.javaClass.getMethod("proceed").invoke(handler)
                                return null
                            }
                        }
                    )
                }
            }
        }
    }

    private fun hookX5WebViewClientSslError(lpparam: LoadPackageParam) {
        if (!isClassExists("com.tencent.smtt.sdk.WebViewClient", lpparam)
            && !isClassExists("com.tencent.smtt.sdk.WebView", lpparam)
            && !isClassExists(
                "com.tencent.smtt.export.external.interfaces.SslErrorHandler",
                lpparam
            )
            && !isClassExists("com.tencent.smtt.export.external.interfaces.SslError", lpparam)
        ) {
            return
        }
        tryHook("X5WebViewClient.onReceivedSslError") {
            XposedHelpers.findAndHookMethod(
                "com.tencent.smtt.sdk.WebViewClient",
                lpparam.classLoader,
                "onReceivedSslError",
                lpparam.classLoader.loadClass("com.tencent.smtt.sdk.WebView"),
                lpparam.classLoader.loadClass("com.tencent.smtt.export.external.interfaces.SslErrorHandler"),
                lpparam.classLoader.loadClass("com.tencent.smtt.export.external.interfaces.SslError"),
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        val handler = param.args[1]
                        handler.javaClass.getMethod("proceed").invoke(handler)
                        return null
                    }
                }
            )
        }
    }

    private fun hookX509TrustManagerExtensions(lpparam: LoadPackageParam) {
        if (!isClassExists("android.net.http.X509TrustManagerExtensions", lpparam)) {
            return
        }

        tryHook("X509TrustManagerExtensions.checkServerTrusted") {
            XposedHelpers.findAndHookMethod(
                "android.net.http.X509TrustManagerExtensions",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return param.args[0] as Array<*>
                    }
                }
            )
        }
    }

    private fun hookXUtils(lpparam: LoadPackageParam) {
        if (!isClassExists("org.xutils.http.RequestParams", lpparam)) {
            return
        }

        tryHook("XUtils RequestParams.setSslSocketFactory") {
            XposedHelpers.findAndHookMethod(
                "org.xutils.http.RequestParams",
                lpparam.classLoader,
                "setSslSocketFactory",
                javax.net.ssl.SSLSocketFactory::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val sslContext = SSLContext.getInstance("TLS")
                        sslContext.init(
                            null,
                            arrayOf<TrustManager>(SSLUtils.createTrustAll()),
                            null
                        )
                        param.args[0] = sslContext.socketFactory
                    }
                }
            )
        }

        tryHook("XUtils RequestParams.setHostnameVerifier") {
            XposedHelpers.findAndHookMethod(
                "org.xutils.http.RequestParams",
                lpparam.classLoader,
                "setHostnameVerifier",
                HostnameVerifier::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = SSLUtils.createTrustAllHostnameVerifier()
                    }
                }
            )
        }
    }

    private fun hookHttpClientAndroidLib(lpparam: LoadPackageParam) {
        if (!isClassExists("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", lpparam)) {
            return
        }

        tryHook("HttpClientAndroidLib AbstractVerifier.verify") {
            XposedHelpers.findAndHookMethod(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier",
                lpparam.classLoader,
                "verify",
                String::class.java,
                Array<String>::class.java,
                Array<String>::class.java,
                Boolean::class.javaPrimitiveType,
                XC_MethodReplacement.DO_NOTHING
            )
        }
    }
}