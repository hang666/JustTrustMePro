package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XC_MethodHook
import just.trust.me.pro.util.SSLUtils
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

class ThirdPartyHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookX509TrustManagerExtensions(lpparam)
        hookXUtils(lpparam)
        hookHttpClientAndroidLib(lpparam)
    }

    private fun hookX509TrustManagerExtensions(lpparam: LoadPackageParam) {
        if (!isClassExists("android.net.http.X509TrustManagerExtensions", lpparam)) {
            return
        }

        val clazz = lpparam.classLoader.loadClass("android.net.http.X509TrustManagerExtensions")
        clazz.declaredMethods
            .filter { it.name == "checkServerTrusted" && !it.isSynthetic }
            .forEach { method ->
                tryHook("X509TrustManagerExtensions.checkServerTrusted(${method.parameterTypes.size})") {
                    XposedHelpers.findAndHookMethod(
                        clazz,
                        method.name,
                        *method.parameterTypes,
                        trustBypassReplacement()
                    )
                }
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