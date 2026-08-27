package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import java.security.cert.X509Certificate

class ConscryptHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookTrustManagerImpl(lpparam)
        hookPlatformChecks(lpparam)
    }

    private fun hookTrustManagerImpl(lpparam: LoadPackageParam) {
        val classNames = listOf(
            "com.android.org.conscrypt.TrustManagerImpl",
            "org.conscrypt.TrustManagerImpl"
        )
        val methodNames = setOf(
            "checkServerTrusted",
            "checkClientTrusted",
            "checkTrusted",
            "checkTrustedRecursive",
            "verifyChain",
            "getTrustedChainForServer"
        )

        for (className in classNames) {
            if (!isClassExists(className, lpparam)) {
                continue
            }

            val clazz = lpparam.classLoader.loadClass(className)
            clazz.declaredMethods
                .filter { it.name in methodNames && !it.isSynthetic }
                .forEach { method ->
                    tryHook("$className.${method.name}(${method.parameterTypes.size})") {
                        XposedHelpers.findAndHookMethod(
                            clazz,
                            method.name,
                            *method.parameterTypes,
                            trustBypassReplacement()
                        )
                    }
                }
        }
    }

    private fun hookPlatformChecks(lpparam: LoadPackageParam) {
        if (!isClassExists("com.android.org.conscrypt.Platform", lpparam)) {
            return
        }

        val platformSignatures = listOf(
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

        for (signature in platformSignatures) {
            tryHook("Platform.checkServerTrusted (${signature.last()})") {
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
}