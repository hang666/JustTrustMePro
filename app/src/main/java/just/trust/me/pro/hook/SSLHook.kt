package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodHook
import java.security.SecureRandom
import just.trust.me.pro.util.SSLUtils
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSocketFactory

class SSLHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookSSLContext(lpparam)
        hookHttpsURLConnection(lpparam)
        hookTrustManagerFactory(lpparam)
    }

    private fun hookSSLContext(lpparam: LoadPackageParam) {
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
                        val emptyTrust = arrayOf(SSLUtils.createTrustAll())
                        param.args[1] = emptyTrust
                    }
                }
            )
        }
    }

    private fun hookHttpsURLConnection(lpparam: LoadPackageParam) {
        tryHook("HttpsURLConnection.setDefaultHostnameVerifier") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.HttpsURLConnection",
                lpparam.classLoader,
                "setDefaultHostnameVerifier",
                HostnameVerifier::class.java,
                returnConstant(null)
            )
        }

        tryHook("HttpsURLConnection.setSSLSocketFactory") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.HttpsURLConnection",
                lpparam.classLoader,
                "setSSLSocketFactory",
                SSLSocketFactory::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = SSLUtils.createTrustAllSSLSocketFactory()
                    }
                }
            )
        }

        tryHook("HttpsURLConnection.setHostnameVerifier") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.HttpsURLConnection",
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

    private fun hookTrustManagerFactory(lpparam: LoadPackageParam) {
        tryHook("TrustManagerFactory.getTrustManagers") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.TrustManagerFactory",
                lpparam.classLoader,
                "getTrustManagers",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result as? Array<*>
                        result?.forEach { manager ->
                            if (manager is javax.net.ssl.X509TrustManager) {
                                hookRootTrustManager(manager.javaClass)
                            }
                        }
                    }
                }
            )
        }
    }

    private fun hookRootTrustManager(clazz: Class<*>) {
        try {
            val methodNames = listOf("checkServerTrusted", "checkClientTrusted")
            methodNames.forEach { methodName ->
                clazz.declaredMethods
                    .filter { it.name == methodName }
                    .forEach { method ->
                        XposedHelpers.findAndHookMethod(
                            clazz,
                            methodName,
                            Array<java.security.cert.X509Certificate>::class.java,
                            String::class.java,
                            returnConstant(null)
                        )
                    }
            }
        } catch (e: Throwable) {
            // Ignore hook failures for individual trust managers
        }
    }

    private fun returnConstant(value: Any?): XC_MethodHook {
        return object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                param.result = value
            }
        }
    }
}