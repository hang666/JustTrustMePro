package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine

class NetworkSecurityHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        if (!isClassExists("android.security.net.config.NetworkSecurityTrustManager", lpparam)) {
            return
        }

        hookNetworkSecurityTrustManager(lpparam)
    }

    private fun hookNetworkSecurityTrustManager(lpparam: LoadPackageParam) {
        // Hook checkServerTrusted methods
        tryHook("NetworkSecurityTrustManager.checkServerTrusted(X509Certificate[], String)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }

        tryHook("NetworkSecurityTrustManager.checkServerTrusted(X509Certificate[], String, Socket)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                Socket::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }

        tryHook("NetworkSecurityTrustManager.checkServerTrusted(X509Certificate[], String, SSLEngine)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                SSLEngine::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }

        tryHook("NetworkSecurityTrustManager.checkServerTrusted(X509Certificate[], String, String)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        // Hook checkClientTrusted methods
        tryHook("NetworkSecurityTrustManager.checkClientTrusted(X509Certificate[], String, Socket)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkClientTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                Socket::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }

        tryHook("NetworkSecurityTrustManager.checkClientTrusted(X509Certificate[], String, SSLEngine)") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkClientTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                SSLEngine::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }

        // Hook checkPins method
        tryHook("NetworkSecurityTrustManager.checkPins") {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader,
                "checkPins",
                List::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }
    }
}