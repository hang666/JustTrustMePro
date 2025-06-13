package just.trust.me.pro.hook

import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodReplacement
import just.trust.me.pro.util.SSLUtils

class WebViewHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookWebViewClient(lpparam)
        hookX5SystemWebViewClientError(lpparam)
        hookX5WebViewClientSslError(lpparam)

        hookSmartSslErrors(lpparam)
    }

    private fun hookWebViewClient(lpparam: LoadPackageParam) {
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


    private fun hookSmartSslErrors(lpparam: LoadPackageParam) {
        if (!isClassExists("com.tencent.smtt.sdk.WebViewClient", lpparam)) {
            return
        }

        val targets = SSLUtils.getSmartSslHookTargets(lpparam.packageName)

        // Hook target classes from smart SSL hook targets
        for (targetClass in targets) {
            if (isClassExists(targetClass, lpparam)) {
                tryHook("SmartSslErrors.hookTargetClass: $targetClass") {
                    val clazz = Class.forName(targetClass, false, lpparam.classLoader)

                    for (method in clazz.declaredMethods) {
                        if (method.name == "onReceivedSslError" && method.parameterTypes.size == 3) {
                            hookSslErrorMethodSmart(clazz.name, method, lpparam)
                        }
                    }
                }
            }
        }

        // Hook classes from class loader scanning
        val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)
        if (classNames.isNotEmpty()) {
            for (className in classNames) {
                if (className.contains("webview", ignoreCase = true) ||
                    className.contains("webclient", ignoreCase = true) ||
                    className.contains("ssl", ignoreCase = true) ||
                    className.contains("web", ignoreCase = true)
                ) {
                    tryHook("SmartSslErrors.hookScannedClass: $className") {
                        val clazz = Class.forName(className, false, lpparam.classLoader)

                        for (method in clazz.declaredMethods) {
                            if (method.name == "onReceivedSslError" && method.parameterTypes.size == 3) {
                                hookSslErrorMethodSmart(clazz.name, method, lpparam)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun hookSslErrorMethodSmart(
        className: String,
        method: java.lang.reflect.Method,
        lpparam: LoadPackageParam
    ) {
        val paramTypes = method.parameterTypes

        tryHook("SmartSslErrors.hookMethod: $className.onReceivedSslError") {
            XposedHelpers.findAndHookMethod(
                className,
                lpparam.classLoader,
                "onReceivedSslError",
                paramTypes[0],
                paramTypes[1],
                paramTypes[2],
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        val handler = param.args[1]

                        val continueMethodNames =
                            listOf("proceed", "continueLoad", "continue", "ignore")

                        for (methodName in continueMethodNames) {
                            try {
                                handler.javaClass.getMethod(methodName).invoke(handler)
                                return null
                            } catch (_: Throwable) {
                            }
                        }

                        return null
                    }
                }
            )
        }
    }
}