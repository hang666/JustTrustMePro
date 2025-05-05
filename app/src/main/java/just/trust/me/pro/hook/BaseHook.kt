package just.trust.me.pro.hook

import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.util.LogUtils

abstract class BaseHook {
    protected fun tryHook(hookName: String, block: () -> Unit) {
        try {
            block()
            LogUtils.hook(hookName, true)
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

    abstract fun initHook(lpparam: LoadPackageParam)
}