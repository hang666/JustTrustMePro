package just.trust.me.pro.util

import android.annotation.SuppressLint
import android.os.Build
import androidx.annotation.RequiresApi
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

object SSLUtils {
    @SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
    fun createTrustAll(): X509TrustManager = object : X509TrustManager {
        @SuppressLint("TrustAllX509TrustManager")
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun createTrustAllHostnameVerifier(): HostnameVerifier {
        return HostnameVerifier { _, _ -> true }
    }

    @SuppressLint("TrustAllX509TrustManager")
    fun createTrustAllSSLSocketFactory(): SSLSocketFactory {
        val trustAll = createTrustAll()
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustAll), SecureRandom())
        return sslContext.socketFactory
    }

    fun allClassNamesFromClassLoader(classLoader: ClassLoader): List<String> {
        val classNames = mutableListOf<String>()
        try {
            if (tryGetClassNamesByBaseDexClassLoader(classLoader, classNames)) {
                return classNames
            }

            if (tryGetClassNamesByPathList(classLoader, classNames)) {
                return classNames
            }

            if (tryGetClassNamesByDexPathList(classLoader, classNames)) {
                return classNames
            }

            if (tryGetClassNamesByParentClassLoader(classLoader, classNames)) {
                return classNames
            }
        } catch (_: Throwable) {
        }
        return classNames
    }

    private fun tryGetClassNamesByBaseDexClassLoader(
        classLoader: ClassLoader,
        classNames: MutableList<String>
    ): Boolean {
        return try {
            val allFields = mutableListOf<java.lang.reflect.Field>()
            var currentClass: Class<*>? = classLoader.javaClass

            while (currentClass != null) {
                allFields.addAll(currentClass.declaredFields)
                currentClass = currentClass.superclass
            }

            val pathListField = allFields.find { field ->
                field.name.contains("pathList", ignoreCase = true) ||
                        field.name.contains("dexPathList", ignoreCase = true) ||
                        field.type.name.contains("DexPathList")
            }

            if (pathListField != null) {
                pathListField.isAccessible = true
                val pathList = pathListField.get(classLoader)

                if (pathList != null) {
                    val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
                    dexElementsField.isAccessible = true
                    val dexElements = dexElementsField.get(pathList) as Array<*>

                    extractClassNamesFromDexElements(dexElements, classNames)
                    return true
                }
            }

            false
        } catch (_: Throwable) {
            false
        }
    }

    private fun tryGetClassNamesByPathList(
        classLoader: ClassLoader,
        classNames: MutableList<String>
    ): Boolean {
        return try {
            val pathListField = classLoader.javaClass.getDeclaredField("pathList")
            pathListField.isAccessible = true
            val pathList = pathListField.get(classLoader)

            val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
            dexElementsField.isAccessible = true
            val dexElements = dexElementsField.get(pathList) as Array<*>

            extractClassNamesFromDexElements(dexElements, classNames)
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun tryGetClassNamesByDexPathList(
        classLoader: ClassLoader,
        classNames: MutableList<String>
    ): Boolean {
        return try {
            val dexPathListField = classLoader.javaClass.getDeclaredField("dexPathList")
            dexPathListField.isAccessible = true
            val dexPathList = dexPathListField.get(classLoader)

            val dexElementsField = dexPathList.javaClass.getDeclaredField("dexElements")
            dexElementsField.isAccessible = true
            val dexElements = dexElementsField.get(dexPathList) as Array<*>

            extractClassNamesFromDexElements(dexElements, classNames)
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun tryGetClassNamesByParentClassLoader(
        classLoader: ClassLoader,
        classNames: MutableList<String>
    ): Boolean {
        return try {
            if (classLoader.javaClass.name.contains("DexClassLoader") ||
                classLoader.javaClass.name.contains("PathClassLoader")
            ) {
                val possibleFields = listOf("pathList", "dexPathList", "mPathList", "mDexPathList")
                for (fieldName in possibleFields) {
                    try {
                        val field = classLoader.javaClass.getDeclaredField(fieldName)
                        field.isAccessible = true
                        val pathList = field.get(classLoader)
                        if (pathList != null) {
                            val dexElementsField =
                                pathList.javaClass.getDeclaredField("dexElements")
                            dexElementsField.isAccessible = true
                            val dexElements = dexElementsField.get(pathList) as Array<*>

                            extractClassNamesFromDexElements(dexElements, classNames)
                            return true
                        }
                    } catch (_: Throwable) {
                    }
                }
            }
            false
        } catch (_: Throwable) {
            false
        }
    }

    private fun extractClassNamesFromDexElements(
        dexElements: Array<*>,
        classNames: MutableList<String>
    ) {
        for (element in dexElements) {
            try {
                val dexFileField = element!!.javaClass.getDeclaredField("dexFile")
                dexFileField.isAccessible = true
                val dexFile = dexFileField.get(element) as? dalvik.system.DexFile
                if (dexFile != null) {
                    val entries = dexFile.entries().toList()
                    classNames.addAll(entries)
                }
            } catch (_: Throwable) {
            }
        }
    }

    fun getSmartSslHookTargets(packageName: String): List<String> {
        val targets = mutableListOf<String>()

        targets.addAll(
            listOf(
                "com.tencent.smtt.sdk.WebViewClient",
                "android.webkit.WebViewClient"
            )
        )

        val packageParts = packageName.split(".")
        val basePackages = mutableListOf<String>()

        for (i in packageParts.indices) {
            basePackages.add(packageParts.take(i + 1).joinToString("."))
        }

        val commonPatterns = listOf(
            "WebViewClient",
            "CustomWebViewClient",
            "MyWebViewClient",
            "BaseWebViewClient",
            "CommonWebViewClient",
            "DefaultWebViewClient"
        )

        val commonPaths = listOf(
            "ui", "web", "webview", "view", "activity", "fragment",
            "base", "common", "util", "utils", "widget", "component",
            "hybrid", "h5", "browser", "client"
        )

        for (basePackage in basePackages) {
            for (pattern in commonPatterns) {
                targets.add("$basePackage.$pattern")
            }

            for (path in commonPaths) {
                for (pattern in commonPatterns) {
                    targets.add("$basePackage.$path.$pattern")
                }
            }
        }

        return targets.distinct()
    }
}