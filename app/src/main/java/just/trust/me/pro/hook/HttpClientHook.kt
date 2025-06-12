package just.trust.me.pro.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import java.net.Socket
import just.trust.me.pro.util.SSLUtils
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.params.HttpParams

class HttpClientHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        if (!isClassExists("org.apache.http.impl.client.DefaultHttpClient", lpparam)) {
            return
        }
        hookDefaultHttpClient(lpparam)
        hookSSLSocketFactory(lpparam)
        hookApacheSSLSocketFactory(lpparam)
    }

    private fun hookDefaultHttpClient(lpparam: LoadPackageParam) {
        // Hook constructor without params
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

        // Hook constructor with params
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
    }

    private fun hookSSLSocketFactory(lpparam: LoadPackageParam) {
        tryHook("SSLSocketFactory.isSecure") {
            XposedHelpers.findAndHookMethod(
                "org.apache.http.conn.ssl.SSLSocketFactory",
                lpparam.classLoader,
                "isSecure",
                Socket::class.java,
                XC_MethodReplacement.returnConstant(true)
            )
        }
    }

    private fun setTrustAllSSLSocketFactory(client: Any) {
        try {
            val sslSocketFactory = SSLUtils.createTrustAllSSLSocketFactory()
            val clientParams = XposedHelpers.callMethod(client, "getParams")
            XposedHelpers.callMethod(
                clientParams,
                "setParameter",
                "http.socket.factory",
                sslSocketFactory
            )
        } catch (e: Throwable) {
            // Ignore if setting SSL socket factory fails
        }
    }

    private fun hookApacheSSLSocketFactory(lpparam: LoadPackageParam) {
        if (!isClassExists("org.apache.http.conn.ssl.SSLSocketFactory", lpparam)) {
            return
        }

        tryHook("Apache SSLSocketFactory constructor") {
            XposedHelpers.findAndHookConstructor(
                "org.apache.http.conn.ssl.SSLSocketFactory",
                lpparam.classLoader,
                String::class.java,
                java.security.KeyStore::class.java,
                String::class.java,
                java.security.KeyStore::class.java,
                java.security.SecureRandom::class.java,
                org.apache.http.conn.scheme.HostNameResolver::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val sslSocketFactory = SSLUtils.createTrustAllSSLSocketFactory()
                            XposedHelpers.setObjectField(
                                param.thisObject,
                                "socketfactory",
                                sslSocketFactory
                            )
                        } catch (e: Throwable) {
                            // Ignore if setting SSL socket factory fails
                        }
                    }
                }
            )
        }

        tryHook("Apache SSLSocketFactory.getSocketFactory") {
            XposedHelpers.findAndHookMethod(
                "org.apache.http.conn.ssl.SSLSocketFactory",
                lpparam.classLoader,
                "getSocketFactory",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            param.result =
                                XposedHelpers.newInstance(
                                    lpparam.classLoader.loadClass(
                                        "org.apache.http.conn.ssl.SSLSocketFactory"
                                    )
                                )
                        } catch (e: Throwable) {
                            // Keep original result if creation fails
                        }
                    }
                }
            )
        }
    }
}
