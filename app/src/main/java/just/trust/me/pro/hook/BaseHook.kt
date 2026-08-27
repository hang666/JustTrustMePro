package just.trust.me.pro.hook

import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.util.LogUtils
import just.trust.me.pro.util.SSLUtils

abstract class BaseHook {
    protected fun tryHook(hookName: String, block: () -> Unit) {
        try {
            block()
            LogUtils.hook(hookName, true)
        } catch (e: Throwable) {
            LogUtils.hook(hookName, false, e)
        }
    }

    protected fun tryHook(hookName: String, showSuccess: Boolean = true, block: () -> Unit) {
        try {
            block()
            if (showSuccess) {
                LogUtils.hook(hookName, true)
            }
        } catch (e: Throwable) {
            LogUtils.hook(hookName, false, e)
        }
    }

    protected fun isClassExists(className: String, lpparam: LoadPackageParam): Boolean {
        return try {
            lpparam.classLoader.loadClass(className)
            true
        } catch (e: Throwable) {
            false
        }
    }

    protected fun trustBypassReplacement(): XC_MethodReplacement {
        return object : XC_MethodReplacement() {
            override fun replaceHookedMethod(param: MethodHookParam): Any? {
                val method = param.method as? java.lang.reflect.Method ?: return null
                return SSLUtils.bypassTrustCheckResult(
                    method.returnType,
                    param.args.firstOrNull()
                )
            }
        }
    }

    abstract fun initHook(lpparam: LoadPackageParam)
}