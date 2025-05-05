package just.trust.me.pro

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.hook.*
import just.trust.me.pro.util.LogUtils

class Main : IXposedHookLoadPackage {
    private val hooks = listOf(
        SSLHook(),
        ConscryptHook(),
        OkHttpHook(),
        WebViewHook(),
        HttpClientHook()
    )

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        LogUtils.debug("Loading hooks for package: ${lpparam.packageName}")
        
        hooks.forEach { hook ->
            try {
                hook.initHook(lpparam)
            } catch (e: Throwable) {
                LogUtils.debug("Failed to initialize ${hook.javaClass.simpleName}: ${e.message}")
            }
        }
        
        LogUtils.debug("All hooks loaded for package: ${lpparam.packageName}")
    }
}