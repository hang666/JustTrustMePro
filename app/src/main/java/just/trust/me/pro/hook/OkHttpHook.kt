package just.trust.me.pro.hook

import android.annotation.SuppressLint
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement

class OkHttpHook : BaseHook() {
    private var certificatePinnerClass: Class<*>? = null
    private var okHostnameVerifierClass: Class<*>? = null
    private val searchedClasses = mutableMapOf<String, Boolean>()

    override fun initHook(lpparam: LoadPackageParam) {
        hookOkHttp(lpparam)
        findAndHookObfuscatedOkHttp(lpparam)
    }

    private fun hookOkHttp(lpparam: LoadPackageParam) {
        // Hook OkHttp3
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

        // Hook OkHttp2
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

    @SuppressLint("PrivateApi")
    private fun findAndHookObfuscatedOkHttp(lpparam: LoadPackageParam) {
        tryHook("OpenSSLSocketFactoryImpl.createSocket") {
            val openSslClass = lpparam.classLoader.loadClass("com.android.org.conscrypt.OpenSSLSocketFactoryImpl")
            XposedBridge.hookAllMethods(
                openSslClass,
                "createSocket",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (certificatePinnerClass == null) {
                            findOkHttpClasses(Throwable().stackTrace, lpparam.classLoader)
                        }
                    }
                }
            )
        }
    }

    private fun findOkHttpClasses(stackTrace: Array<StackTraceElement>, classLoader: ClassLoader) {
        val realConnectionClass = findRealConnectionClass(stackTrace, classLoader) ?: return

        // Find Route class
        val routeClass = findRouteClass(realConnectionClass) ?: return

        // Find Address class
        val addressClass = findAddressClass(routeClass, classLoader) ?: return

        // Hook Address constructor to replace CertificatePinner
        hookAddressConstructor(addressClass)
    }

    private fun findRealConnectionClass(stackTrace: Array<StackTraceElement>, classLoader: ClassLoader): Class<*>? {
        return stackTrace
            .map { it.className }
            .filter { !searchedClasses.containsKey(it) }
            .firstNotNullOfOrNull { className ->
                searchedClasses[className] = true
                try {
                    val clazz = classLoader.loadClass(className)
                    if (isRealConnectionClass(clazz)) clazz else null
                } catch (e: Throwable) {
                    null
                }
            }
    }

    private fun isRealConnectionClass(clazz: Class<*>): Boolean {
        return clazz.declaredFields.any { field ->
            field.type == Boolean::class.javaPrimitiveType && field.name == "noNewStreams"
        }
    }

    private fun findRouteClass(realConnectionClass: Class<*>): Class<*>? {
        return realConnectionClass.declaredFields.firstOrNull { field ->
            field.type.declaredFields.any { it.name == "address" }
        }?.type
    }

    private fun findAddressClass(routeClass: Class<*>, classLoader: ClassLoader): Class<*>? {
        val addressClassName = routeClass.declaredFields
            .firstOrNull { it.name == "address" }
            ?.type
            ?.name
            ?: return null

        return try {
            classLoader.loadClass(addressClassName)
        } catch (e: Throwable) {
            null
        }
    }

    private fun hookAddressConstructor(addressClass: Class<*>) {
        tryHook("Address constructor") {
            XposedBridge.hookAllConstructors(
                addressClass,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val certificatePinnerIndex = param.args.indexOfFirst {
                            it?.javaClass == certificatePinnerClass
                        }
                        if (certificatePinnerIndex != -1) {
                            // Replace CertificatePinner with default instance
                            param.args[certificatePinnerIndex] = XposedHelpers.callStaticMethod(
                                certificatePinnerClass,
                                "get"
                            )
                        }
                    }
                }
            )
        }
    }
}