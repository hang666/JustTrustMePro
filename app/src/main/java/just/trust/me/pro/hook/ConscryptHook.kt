package just.trust.me.pro.hook

import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XC_MethodHook
import java.security.cert.X509Certificate

class ConscryptHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        if (!isClassExists("com.android.org.conscrypt.TrustManagerImpl", lpparam)) {
            return
        }

        hookTrustManagerImpl(lpparam)
        hookPlatformChecks(lpparam)
    }

    private fun hookTrustManagerImpl(lpparam: LoadPackageParam) {
        // Basic server trust checks
        tryHook("TrustManagerImpl.checkServerTrusted(X509Certificate[], String)") {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        tryHook("TrustManagerImpl.checkServerTrusted(X509Certificate[], String, String)") {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        tryHook("TrustManagerImpl.checkServerTrusted(X509Certificate[], String, SSLSession)") {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                javax.net.ssl.SSLSession::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        // Hook additional checkTrusted methods
        tryHook("TrustManagerImpl.checkTrusted(X509Certificate[], String, SSLSession, SSLParameters, boolean)") {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                javax.net.ssl.SSLSession::class.java,
                javax.net.ssl.SSLParameters::class.java,
                Boolean::class.javaPrimitiveType,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        tryHook("TrustManagerImpl.checkTrusted(X509Certificate[], ByteArray, ByteArray, String, String, boolean)") {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkTrusted",
                Array<X509Certificate>::class.java,
                ByteArray::class.java,
                ByteArray::class.java,
                String::class.java,
                String::class.java,
                Boolean::class.javaPrimitiveType,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return ArrayList<X509Certificate>()
                    }
                }
            )
        }

        // Hook checkTrustedRecursive methods dynamically
        hookCheckTrustedRecursive(lpparam)

        // Chain verification
        val verifyChainSignatures = listOf(
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

        for (signature in verifyChainSignatures) {
            tryHook("TrustManagerImpl.verifyChain (${signature.size} params)") {
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

    private fun hookCheckTrustedRecursive(lpparam: LoadPackageParam) {
        tryHook("TrustManagerImpl.checkTrustedRecursive (dynamic)") {
            val clazz = lpparam.classLoader.loadClass("com.android.org.conscrypt.TrustManagerImpl")

            clazz.declaredMethods.forEach { method ->
                if (method.name == "checkTrustedRecursive" && method.returnType == List::class.java) {
                    XposedHelpers.findAndHookMethod(
                        clazz,
                        method.name,
                        *method.parameterTypes,
                        object : XC_MethodReplacement() {
                            override fun replaceHookedMethod(param: MethodHookParam): Any {
                                return ArrayList<X509Certificate>()
                            }
                        }
                    )
                }
            }
        }
    }
}