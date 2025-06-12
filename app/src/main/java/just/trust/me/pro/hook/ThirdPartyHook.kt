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
                        return param.args[0] as Array<X509Certificate>
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