package just.trust.me.pro.hook

import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import java.net.InetSocketAddress
import java.net.Proxy

class ProxyHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookProxySettings()
    }

    private fun hookProxySettings() {
        tryHook("Proxy.NO_PROXY replacement") {
            val httpProxy = System.getProperty("http.proxyHost")
            val httpPort = System.getProperty("http.proxyPort")
            val httpsProxy = System.getProperty("https.proxyHost")
            val httpsPort = System.getProperty("https.proxyPort")

            val proxyHost = httpProxy ?: httpsProxy
            val proxyPort = httpPort ?: httpsPort

            if (!proxyHost.isNullOrBlank() && !proxyPort.isNullOrBlank()) {
                val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(proxyHost, proxyPort.toInt()))

                // Replace NO_PROXY with actual proxy
                val field = Proxy::class.java.getDeclaredField("NO_PROXY")
                field.isAccessible = true
                field.set(null, proxy)
            }
        }
    }
}