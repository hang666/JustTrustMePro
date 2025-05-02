package just.trust.me.pro

import android.annotation.SuppressLint
import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.params.HttpParams
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier

class Main : IXposedHookLoadPackage {
    object SslBypassHooks {
        fun hookAll(lpparam: XC_LoadPackage.LoadPackageParam) {
            hookSSLContext(lpparam)
            hookTrustManagerImplVerifyChain(lpparam)
            hookOkHttp(lpparam)
            hookWebView(lpparam)
            hookHttpClient(lpparam)
            hookXUtils(lpparam)
            hookConscryptPlatform(lpparam)
            hookPinningTrustManager(lpparam)
            hookX509TrustManagerExtensions(lpparam)
            hookNetworkSecurityTrustManager(lpparam)
        }

        private fun hookSSLContext(lpparam: XC_LoadPackage.LoadPackageParam) {
            tryHook("SSLContext.init") {
                XposedHelpers.findAndHookMethod(
                    "javax.net.ssl.SSLContext",
                    lpparam.classLoader,
                    "init",
                    Array<javax.net.ssl.KeyManager>::class.java,
                    Array<javax.net.ssl.TrustManager>::class.java,
                    SecureRandom::class.java,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val emptyTrust = arrayOf<javax.net.ssl.TrustManager>(createTrustAll())
                            param.args[1] = emptyTrust
                        }
                    }
                )
            }
        }

        private fun hookWebView(lpparam: XC_LoadPackage.LoadPackageParam) {
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

        private fun hookHttpClient(lpparam: XC_LoadPackage.LoadPackageParam) {
            if (!isClassExists("org.apache.http.impl.client.DefaultHttpClient", lpparam)) {
                LogUtils.debug("- DefaultHttpClient not found, skipping hooks")
                return
            }

            tryHook("DefaultHttpClient constructor") {
                XposedHelpers.findAndHookConstructor(
                    DefaultHttpClient::class.java,
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            setTrustAllSSLSocketFactory(param.thisObject)
                        }
                    }
                )
            }

            tryHook("DefaultHttpClient constructor with params") {
                XposedHelpers.findAndHookConstructor(
                    DefaultHttpClient::class.java,
                    HttpParams::class.java,
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            setTrustAllSSLSocketFactory(param.thisObject)
                        }
                    }
                )
            }

            tryHook("SSLSocketFactory.isSecure") {
                XposedHelpers.findAndHookMethod(
                    "org.apache.http.conn.ssl.SSLSocketFactory",
                    lpparam.classLoader,
                    "isSecure",
                    java.net.Socket::class.java,
                    XC_MethodReplacement.returnConstant(true)
                )
            }
        }


        private fun hookXUtils(lpparam: XC_LoadPackage.LoadPackageParam) {
            if (!isClassExists("org.xutils.http.RequestParams", lpparam)) {
                LogUtils.debug("- XUtils not found, skipping hooks")
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
                            param.args[0] = createTrustAllSSLSocketFactory()
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
                            param.args[0] = createTrustAllHostnameVerifier()
                        }
                    }
                )
            }
        }

        private fun hookOkHttp(lpparam: XC_LoadPackage.LoadPackageParam) {
            // Hook OkHttp 3.x
            tryHook("OkHttp3 CertificatePinner.check") {
                XposedHelpers.findAndHookMethod(
                    "okhttp3.CertificatePinner",
                    lpparam.classLoader,
                    "check",
                    String::class.java,
                    List::class.java,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = Unit
                        }
                    }
                )
            }

            // Hook OkHttp 2.x
            tryHook("OkHttp2 CertificatePinner.check") {
                XposedHelpers.findAndHookMethod(
                    "com.squareup.okhttp.CertificatePinner",
                    lpparam.classLoader,
                    "check",
                    String::class.java,
                    List::class.java,
                    object : XC_MethodReplacement() {
                        override fun replaceHookedMethod(param: MethodHookParam) = true
                    }
                )
            }
        }

        private fun hookConscryptPlatform(lpparam: XC_LoadPackage.LoadPackageParam) {
            if (!isClassExists("com.android.org.conscrypt.Platform", lpparam)) {
                LogUtils.debug("- Platform not found, skipping hooks")
                return
            }

            val methodSignatures = listOf(
                arrayOf(
                    javax.net.ssl.X509TrustManager::class.java,
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    "com.android.org.conscrypt.OpenSSLEngineImpl"
                ),
                arrayOf(
                    javax.net.ssl.X509TrustManager::class.java,
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    "com.android.org.conscrypt.OpenSSLSocketImpl"
                ),
                arrayOf(
                    javax.net.ssl.X509TrustManager::class.java,
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    "com.android.org.conscrypt.AbstractConscryptSocket"
                ),
                arrayOf(
                    javax.net.ssl.X509TrustManager::class.java,
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    "com.android.org.conscrypt.ConscryptEngine"
                )
            )

            for (signature in methodSignatures) {
                tryHook("Platform.checkServerTrusted") {
                    XposedHelpers.findAndHookMethod(
                        "com.android.org.conscrypt.Platform",
                        lpparam.classLoader,
                        "checkServerTrusted",
                        *signature,
                        object : XC_MethodReplacement() {
                            override fun replaceHookedMethod(param: MethodHookParam): Any? {
                                return null
                            }
                        }
                    )
                }
            }
        }

        private fun hookPinningTrustManager(lpparam: XC_LoadPackage.LoadPackageParam) {
            if (!isClassExists("appcelerator.https.PinningTrustManager", lpparam)) {
                LogUtils.debug("- PinningTrustManager not found, skipping hooks")
                return
            }

            tryHook("PinningTrustManager.checkServerTrusted") {
                XposedHelpers.findAndHookMethod(
                    "appcelerator.https.PinningTrustManager",
                    lpparam.classLoader,
                    "checkServerTrusted",
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    object : XC_MethodReplacement() {
                        override fun replaceHookedMethod(param: MethodHookParam): Any? {
                            return null
                        }
                    }
                )
            }
        }

        private fun hookX509TrustManagerExtensions(lpparam: XC_LoadPackage.LoadPackageParam) {
            tryHook("X509TrustManagerExtensions.checkServerTrusted") {
                XposedHelpers.findAndHookMethod(
                    "android.net.http.X509TrustManagerExtensions",
                    lpparam.classLoader,
                    "checkServerTrusted",
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    String::class.java,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = listOf(*param.args[0] as Array<*>)
                        }
                    }
                )
            }
        }

        private fun hookNetworkSecurityTrustManager(lpparam: XC_LoadPackage.LoadPackageParam) {
            if (!isClassExists(
                    "android.security.net.config.NetworkSecurityTrustManager",
                    lpparam
                )
            ) {
                LogUtils.debug("- NetworkSecurityTrustManager not found, skipping hooks")
                return
            }

            tryHook("NetworkSecurityTrustManager.checkPins") {
                XposedHelpers.findAndHookMethod(
                    "android.security.net.config.NetworkSecurityTrustManager",
                    lpparam.classLoader,
                    "checkPins",
                    List::class.java,
                    object : XC_MethodReplacement() {
                        override fun replaceHookedMethod(param: MethodHookParam): Any? {
                            return null
                        }
                    }
                )
            }
        }

        private fun hookTrustManagerImplVerifyChain(lpparam: XC_LoadPackage.LoadPackageParam) {
            val methodSignatures = listOf(
                arrayOf(
                    Array<X509Certificate>::class.java,
                    MutableList::class.java,
                    String::class.java,
                    Boolean::class.javaPrimitiveType,
                    ByteArray::class.java,
                    Any::class.java
                ),
                arrayOf(
                    Array<X509Certificate>::class.java,
                    java.util.List::class.java,
                    String::class.java,
                    Boolean::class.javaPrimitiveType,
                    ByteArray::class.java,
                    Any::class.java
                ),
                arrayOf(
                    Array<X509Certificate>::class.java,
                    java.util.List::class.java,
                    String::class.java,
                    Boolean::class.javaPrimitiveType
                )
            )

            for (signature in methodSignatures) {
                try {
                    XposedHelpers.findAndHookMethod(
                        "com.android.org.conscrypt.TrustManagerImpl",
                        lpparam.classLoader,
                        "verifyChain",
                        *signature,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = param.args[0]
                            }
                        }
                    )
                    LogUtils.hook("TrustManagerImpl.verifyChain (${signature.size} params)", true)
                    break
                } catch (e: Throwable) {
                    LogUtils.hook(
                        "TrustManagerImpl.verifyChain (${signature.size} params)",
                        false,
                        e
                    )
                }
            }
        }

        // Helper functions
        private fun tryHook(hookName: String, block: () -> Unit) {
            try {
                block()
                LogUtils.hook(hookName, true)
            } catch (e: Throwable) {
                LogUtils.hook(hookName, false, e)
            }
        }

        private fun isClassExists(
            className: String,
            lpparam: XC_LoadPackage.LoadPackageParam
        ): Boolean {
            return try {
                lpparam.classLoader.loadClass(className)
                true
            } catch (e: ClassNotFoundException) {
                false
            }
        }

        @SuppressLint("CustomX509TrustManager")
        private fun createTrustAll() = object : javax.net.ssl.X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(
                chain: Array<X509Certificate>,
                authType: String
            ) {
            }

            @SuppressLint("TrustAllX509TrustManager")
            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String
            ) {
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        private fun createTrustAllHostnameVerifier() = HostnameVerifier { _, _ -> true }

        private fun createTrustAllSSLSocketFactory(): javax.net.ssl.SSLSocketFactory {
            val context = javax.net.ssl.SSLContext.getInstance("TLS")
            context.init(null, arrayOf(createTrustAll()), SecureRandom())
            return context.socketFactory
        }

        private fun setTrustAllSSLSocketFactory(client: Any) {
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
            trustStore.load(null, null)
            XposedHelpers.callMethod(
                client,
                "setSSLSocketFactory",
                createTrustAllSSLSocketFactory()
            )
        }
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam?) {
        lpparam?.let { SslBypassHooks.hookAll(it) }
    }

    object LogUtils {
        private const val TAG = "JustTrustMePro"

        fun info(message: String) = android.util.Log.i(TAG, message)
        fun error(message: String) = android.util.Log.e(TAG, message)
        fun debug(message: String) = android.util.Log.d(TAG, message)
        fun warn(message: String) = android.util.Log.w(TAG, message)

        fun hook(name: String, success: Boolean, error: Throwable? = null) {
            if (success) {
                debug("✓ $name")
            } else if (error != null) {
                warn("✗ $name: ${error.message}")
            } else {
                debug("✗ $name")
            }
        }
    }
}