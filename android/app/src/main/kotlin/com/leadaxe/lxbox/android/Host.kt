package com.leadaxe.lxbox.android

import android.Manifest
import android.app.ActivityManager
import android.app.Application
import android.os.Debug
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class LxBoxApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        app = this
        File(filesDir, "sub_cache").mkdirs()
        File(applicationInfo.dataDir, "app_flutter").mkdirs()
        NativeBridge.bootstrap(applicationInfo.dataDir)
    }

    companion object {
        @Volatile lateinit var app: LxBoxApplication
            private set
        val connectivity: ConnectivityManager
            get() = app.getSystemService(ConnectivityManager::class.java)
        val prefs get() = app.getSharedPreferences("native_prefs", Context.MODE_PRIVATE)
    }
}

object NativeBridge {
    private const val LIBRARY = "lxbox"
    @Volatile private var loaded = false
    @Volatile private var host: Host? = null

    @Synchronized fun load() {
        if (loaded) return
        System.loadLibrary(LIBRARY)
        loaded = true
    }

    @Synchronized fun bootstrap(dataDir: String) {
        load()
        if (host != null) return
        val platform = Host(LxBoxApplication.app)
        host = platform
        val result = JSONObject(nativeBootstrap(dataDir, platform))
        if (!result.optBoolean("ok")) {
            host = null
            throw IllegalStateException(result.optJSONObject("error")?.optString("message") ?: "Go runtime bootstrap failed")
        }
    }

    fun appCall(method: String, args: JSONObject = JSONObject()): JSONObject {
        load()
        val response = JSONObject(nativeAppCall(method, args.toString()))
        if (!response.optBoolean("ok")) {
            throw IllegalStateException(response.optJSONObject("error")?.optString("message") ?: "Go call failed: $method")
        }
        return response
    }

    private external fun nativeBootstrap(dataDir: String, host: Host): String
    private external fun nativeAppCall(method: String, argsJson: String): String
}

class Host(private val context: Context) {
    init { current = this }
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val monitors = HashMap<Long, ConnectivityManager.NetworkCallback>()
    private val callbackLock = Any()
    private var openConnect: OpenConnectCallbackServer? = null
    private val streams = ConcurrentHashMap<String, StreamEntry>()
    private val appFunctionsScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private data class StreamEntry(
        val input: InputStream? = null,
        val output: OutputStream? = null,
        val uri: android.net.Uri? = null,
    )


    fun call(method: String, argsJson: String): String {
        try {
            val args = if (argsJson.isBlank()) JSONObject() else JSONObject(argsJson)
            return dispatch(method, args).toString()
        } catch (t: Throwable) {
            Log.e(TAG, "platform.$method failed", t)
            throw IllegalStateException("platform.$method: ${t.message ?: t.javaClass.simpleName}", t)
        }
    }

    private fun dispatch(method: String, a: JSONObject): Any = when (method) {
        "memory.get", "getMemoryInfo" -> memoryGet()
        "paths" -> paths()
        "core.setup" -> coreSetup()
        "vpn.status" -> JSONObject().put("state", BoxVpnService.status).put("running", BoxVpnService.running)
        "dns.capabilities" -> dnsCapabilities()
        "dns.lookup" -> dnsLookup(a)
        "dns.exchange" -> dnsExchange(a)
        "vpn.start" -> {
            requestVpnStart(BoxVpnService.ACTION_START, a.optString("config"))
            JSONObject().put("accepted", true).put("consentPending", VpnService.prepare(context) != null)
        }
        "vpn.reload" -> {
            requestVpnStart(BoxVpnService.ACTION_RELOAD, a.optString("config"))
            JSONObject().put("accepted", true).put("consentPending", VpnService.prepare(context) != null)
        }
        "vpn.stop" -> {
            startCoreService(BoxVpnService.ACTION_STOP, "")
            JSONObject().put("accepted", true)
        }
        "vpn.openTun" -> JSONObject().put("fd", openTun(a))
        "network.protect" -> {
            val fd = a.getInt("fd")
            val service = BoxVpnService.live
            if (service != null) {
                if (!service.protect(fd)) throw IllegalStateException("VpnService.protect($fd) returned false")
            } else {
                val network = physicalNetwork(connectivity) ?: throw IllegalStateException("no physical network available to protect socket")
                ParcelFileDescriptor.fromFd(fd).use { duplicate -> network.bindSocket(duplicate.fileDescriptor) }
            }
            JSONObject().put("protected", true)
        }
        "network.interfaces" -> interfaces()
        "network.connectionOwner" -> connectionOwner(a)
        "network.wifi" -> wifiState()
        "network.monitor.start" -> monitorStart(a)
        "network.monitor.stop" -> monitorStop(a)
        "network.monitor.poll" -> monitorPoll(a)
        "network.registerMyInterface" -> throw UnsupportedOperationException("registering external interfaces is not supported on Android")
        "dns.clear" -> throw UnsupportedOperationException("Android does not expose a public DNS resolver-cache clear API")
        "notification.send" -> sendNotification(a)
        "notification.cancel" -> cancelNotification(a)
        "events.emit" -> emit("com.leadaxe.lxbox.EVENT", a)
        "automation.emit" -> emit("com.leadaxe.lxbox.AUTOMATION", a)
        "path_mtu.network" -> PathMtuProbe.network(context)
        "path_mtu.resolve" -> PathMtuProbe.resolve(context, a.getString("target"))
        "path_mtu.probe" -> PathMtuProbe.probe(context, a)
        "saf.import", "transfer.saf.import" -> safImport(a).get(10, TimeUnit.MINUTES)
        "saf.export", "transfer.saf.export" -> safExport(a).get(10, TimeUnit.MINUTES)
        "file.pick" -> filePick(a).get(10, TimeUnit.MINUTES)
        "file.read" -> fileRead(a)
        "file.readChunk" -> fileReadChunk(a)
        "file.openRead" -> fileOpenRead(a)
        "file.create" -> fileCreate(a).get(10, TimeUnit.MINUTES)
        "file.writeChunk" -> fileWriteChunk(a)
        "file.close" -> fileClose(a)
        "openconnect.callback.start" -> openConnectStart(a)
        "openconnect.callback.stop" -> openConnectStop()
        "lan.post" -> lanPost(a)
        "apps.list" -> appsList()
        "apps.info" -> appInfo(a)
        "apps.icon" -> appIcon(a)
        "clipboard.get" -> clipboardGet()
        "clipboard.set" -> clipboardSet(a)
        "permission.check" -> JSONObject().put("granted", hasPermission(a.getString("permission")))
        "permission.request" -> permissionRequest(a)
        "nativeprefs.apply" -> nativePrefsApply(a)
        "nativeprefs.get" -> nativePrefsGet(a)
        "nativeprefs.set" -> nativePrefsSet(a)
        "theme.get" -> JSONObject().put("mode", LxBoxApplication.prefs.getString("app_theme_mode", "system"))
        "theme.set" -> nativePrefsSet(JSONObject().put("key", "app_theme_mode").put("value", a.getString("mode")))
        "language.get" -> JSONObject().put("tag", LxBoxApplication.prefs.getString("app_language", "system"))
        "language.set" -> nativePrefsSet(JSONObject().put("key", "app_language").put("value", a.getString("tag")))
        else -> throw UnsupportedOperationException("unknown Android platform method: $method")
    }

    private fun dnsCapabilities(): JSONObject = JSONObject().put("raw", Build.VERSION.SDK_INT >= 29)

    private fun dnsLookup(a: JSONObject): JSONObject {
        val domain = a.getString("domain")
        val network = physicalNetwork(connectivity) ?: throw IllegalStateException("no physical network")
        val family = a.optString("network", "ip4")
        val addresses = network.getAllByName(domain).filter {
            if (family == "ip6") it is Inet6Address else it is java.net.Inet4Address
        }
        return JSONObject().put("addresses", JSONArray(addresses.mapNotNull { it.hostAddress }))
            .put("rcode", if (addresses.isEmpty()) 3 else 0)
    }

    @androidx.annotation.RequiresApi(29)
    private fun dnsExchange(a: JSONObject): JSONObject {
        if (Build.VERSION.SDK_INT < 29) throw UnsupportedOperationException("raw DNS exchange requires Android 10 or newer")
        val network = physicalNetwork(connectivity) ?: throw IllegalStateException("no physical network")
        val message = Base64.decode(a.getString("message"), Base64.DEFAULT)
        val done = java.util.concurrent.CountDownLatch(1)
        var response: ByteArray? = null
        var responseCode: Int? = null
        var failure: Throwable? = null
        val cancellation = CancellationSignal()
        DnsResolver.getInstance().rawQuery(
            network, message, DnsResolver.FLAG_EMPTY, HostWorkers.dnsExecutor, cancellation,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(answer: ByteArray, rcode: Int) { response = answer; responseCode = rcode; done.countDown() }
                override fun onError(error: DnsResolver.DnsException) { failure = error; done.countDown() }
            },
        )
        if (!done.await(DNS_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            cancellation.cancel()
            throw SocketTimeoutException("physical DNS exchange timed out")
        }
        failure?.let { throw IllegalStateException("physical DNS exchange failed: ${it.message}", it) }
        val packet = response ?: throw IllegalStateException("physical DNS exchange returned no packet")
        return JSONObject().put("message", Base64.encodeToString(packet, Base64.NO_WRAP)).put("rcode", responseCode ?: 0)
    }

    private fun memoryGet(): JSONObject {
        val manager = context.getSystemService(ActivityManager::class.java)
        val system = ActivityManager.MemoryInfo().also(manager::getMemoryInfo)
        val process = Debug.MemoryInfo().also(Debug::getMemoryInfo)
        return JSONObject().put("availMem", system.availMem).put("totalMem", system.totalMem)
            .put("threshold", system.threshold).put("lowMemory", system.lowMemory)
            .put("pssKb", process.totalPss).put("nativePssKb", process.nativePss)
            .put("dalvikPssKb", process.dalvikPss).put("otherPssKb", process.otherPss)
            .put("maxHeapBytes", Runtime.getRuntime().maxMemory())
            .put("usedHeapBytes", Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())
    }

    private fun coreSetup(): JSONObject {
        val prefs = LxBoxApplication.prefs
        val limitBytes = when (prefs.getString("memory_limit", "auto")) {
            "200" -> 200L * 1024 * 1024
            "384" -> 384L * 1024 * 1024
            "512" -> 512L * 1024 * 1024
            "768" -> 768L * 1024 * 1024
            else -> 0L
        }
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
        return JSONObject().put("debug", prefs.getBoolean("core_logs_enabled", false))
            .put("oomKillerEnabled", true).put("oomKillerDisabled", false)
            .put("oomMemoryLimit", limitBytes).put("oomMemoryLimitHeap", true)
            .put("powerReportEnabled", true).put("appVersion", packageInfo.versionName ?: "")
            .put("appMarketingVersion", packageInfo.versionName ?: "")
    }

    private fun paths() = JSONObject()
        .put("cacheDir", File(context.filesDir, "sub_cache").also { it.mkdirs() }.absolutePath)
        .put("supportDir", context.filesDir.absolutePath)
        .put("documentsDir", File(context.applicationInfo.dataDir, "app_flutter").also { it.mkdirs() }.absolutePath)

    private fun requestVpnStart(action: String, config: String) {
        val activity = MainActivity.current
        if (activity == null) {
            if (VpnService.prepare(context) != null) {
                throw SecurityException("VPN consent is required; open LxBox once to grant it")
            }
            startCoreService(action, config)
            return
        }
        if (!MainActivity.requestVpnConsent(context, action, config)) {
            throw IllegalStateException("VPN consent request could not be scheduled")
        }
    }

    private fun startCoreService(action: String, config: String) {
        val intent = Intent(context, BoxVpnService::class.java).setAction(action)
            .putExtra(BoxVpnService.EXTRA_CONFIG, config)
        ContextCompat.startForegroundService(context, intent)
    }

    private fun openTun(a: JSONObject): Int {
        val service = BoxVpnService.live ?: error("VpnService is not running")
        if (VpnService.prepare(context) != null) throw SecurityException("VPN consent has not been granted")
        val builder = service.newBuilder().setSession("LxBox")
        a.optInt("mtu", 0).takeIf { it > 0 }?.let(builder::setMtu)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        addPrefixes(a.optJSONArray("inet4Address"), builder::addAddress)
        addPrefixes(a.optJSONArray("inet6Address"), builder::addAddress)
        a.optJSONArray("dnsServers").strings().forEach(builder::addDnsServer)

        val routes4 = a.optJSONArray("inet4RouteAddress").nonEmptyStrings()
        val routes6 = a.optJSONArray("inet6RouteAddress").nonEmptyStrings()
        val legacy4 = a.optJSONArray("inet4RouteRange").nonEmptyStrings()
        val legacy6 = a.optJSONArray("inet6RouteRange").nonEmptyStrings()
        if (a.optBoolean("autoRoute", true)) {
            (routes4.ifEmpty { legacy4.ifEmpty { listOf("0.0.0.0/0") } } +
                routes6.ifEmpty { legacy6.ifEmpty { listOf("::/0") } }).forEach { addRoute(builder, it) }
        }
        val excluded = a.optJSONArray("inet4RouteExcludeAddress").nonEmptyStrings() +
            a.optJSONArray("inet6RouteExcludeAddress").nonEmptyStrings()
        if (excluded.isNotEmpty()) {
            if (Build.VERSION.SDK_INT < 33) error("VPN route exclusions require Android 13 or newer")
            excluded.forEach { raw ->
                val slash = raw.lastIndexOf('/')
                require(slash > 0) { "invalid excluded route: $raw" }
                builder.excludeRoute(android.net.IpPrefix(InetAddress.getByName(raw.substring(0, slash)), raw.substring(slash + 1).toInt()))
            }
        }
        addPackages(a.optJSONArray("includePackage"), true, builder)
        addPackages(a.optJSONArray("excludePackage"), false, builder)
        val proxy = a.optJSONObject("httpProxy")
        val proxyEnabled = proxy?.optBoolean("enabled", false) ?: a.optBoolean("isHTTPProxyEnabled")
        val proxyServer = proxy?.optString("server").orEmpty().ifBlank { a.optString("httpProxyServer") }
        val proxyPort = proxy?.optInt("serverPort", 0) ?: a.optInt("httpProxyServerPort")
        val proxyBypass = proxy?.optJSONArray("bypassDomain")?.strings()
            ?: a.optJSONArray("httpProxyBypassDomain").strings()
        val proxyMatch = proxy?.optJSONArray("matchDomain")?.strings().orEmpty()
        if (proxyEnabled && proxyServer.isNotBlank()) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                throw UnsupportedOperationException("VPN HTTP proxy requires Android 10 (API 29) or newer")
            }
            if (proxyMatch.isNotEmpty()) {
                throw UnsupportedOperationException("Android VpnService HTTP proxy cannot restrict interception to matchDomain")
            }
            require(proxyPort in 1..65535) { "invalid VPN HTTP proxy port: $proxyPort" }
            builder.setHttpProxy(ProxyInfo.buildDirectProxy(proxyServer, proxyPort, proxyBypass))
        }
        val descriptor = builder.establish() ?: error("VpnService.Builder.establish returned null")
        service.replaceTun(descriptor)
        return descriptor.fd
    }

    private fun addRoute(builder: VpnService.Builder, raw: String) {
        val slash = raw.lastIndexOf('/')
        require(slash > 0) { "invalid route: $raw" }
        builder.addRoute(android.net.IpPrefix(InetAddress.getByName(raw.substring(0, slash)), raw.substring(slash + 1).toInt()))
    }

    private fun addPackages(values: JSONArray?, allow: Boolean, builder: VpnService.Builder) {
        values.strings().forEach { name ->
            try {
                if (allow) builder.addAllowedApplication(name) else builder.addDisallowedApplication(name)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "VPN package not installed: $name")
            }
        }
    }

    private fun interfaces(): JSONArray {
        val result = JSONArray()
        val system = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().associateBy { it.name }
        for (network in connectivity.allNetworks) {
            val props = connectivity.getLinkProperties(network) ?: continue
            val caps = connectivity.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val ni = system[props.interfaceName] ?: continue
            val addresses = JSONArray()
            ni.interfaceAddresses.forEach { addresses.put("${it.address.hostAddress}/${it.networkPrefixLength}") }
            val dns = JSONArray().also { out -> props.dnsServers.forEach { out.put(it.hostAddress) } }
            val gateways = JSONArray().also { out -> props.routes.mapNotNull { it.gateway?.hostAddress }.distinct().forEach(out::put) }
            var flags = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            if (ni.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
            if (ni.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
            if (ni.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
            val type = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 2
                else -> 3
            }
            result.put(JSONObject().put("index", ni.index).put("mtu", runCatching { ni.mtu }.getOrDefault(0))
                .put("name", ni.name).put("addresses", addresses).put("flags", flags).put("type", type)
                .put("dnsServer", dns).put("gateway", gateways)
                .put("metered", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)))
        }
        return result
    }

    private fun physicalNetwork(cm: ConnectivityManager): Network? {
        val active = cm.activeNetwork
        if (active != null && isPhysical(cm, active)) return active
        return cm.allNetworks.firstOrNull { isPhysical(cm, it) }
    }

    private fun isPhysical(cm: ConnectivityManager, network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun connectionOwner(a: JSONObject): JSONObject {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) error("connection owner lookup requires Android 10 or newer")
        val uid = connectivity.getConnectionOwnerUid(
            a.getInt("ipProtocol"),
            InetSocketAddress(a.getString("sourceAddress"), a.getInt("sourcePort")),
            InetSocketAddress(a.getString("destinationAddress"), a.getInt("destinationPort")),
        )
        if (uid == Process.INVALID_UID) return JSONObject().put("userId", uid).put("androidPackageNames", JSONArray())
        val packages = context.packageManager.getPackagesForUid(uid).orEmpty()
        return JSONObject().put("userId", uid).put("userName", packages.firstOrNull() ?: "")
            .put("processPath", "").put("androidPackageNames", JSONArray(packages))
    }

    @Suppress("DEPRECATION")
    private fun wifiState(): JSONObject {
        if (Build.VERSION.SDK_INT >= 33 && !hasPermission(Manifest.permission.NEARBY_WIFI_DEVICES)) {
            throw SecurityException("NEARBY_WIFI_DEVICES permission is required to read Wi-Fi state")
        }
        if (!hasPermission(Manifest.permission.ACCESS_FINE_LOCATION)) {
            throw SecurityException("ACCESS_FINE_LOCATION permission is required to read Wi-Fi state")
        }
        // Foreground callbacks only need FINE_LOCATION. Background calls must
        // also hold BACKGROUND_LOCATION; Go platform callbacks are background.
        if (Build.VERSION.SDK_INT >= 29 && !isForeground() && !hasPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            throw SecurityException("ACCESS_BACKGROUND_LOCATION permission is required to read Wi-Fi state in background")
        }
        val info = wifi.connectionInfo ?: return JSONObject().put("ssid", "").put("bssid", "")
        val ssid = info.ssid?.removeSurrounding("\"")?.takeUnless { it == "<unknown ssid>" }.orEmpty()
        val bssid = info.bssid?.lowercase()?.takeUnless { it == "02:00:00:00:00:00" }.orEmpty()
        return JSONObject().put("ssid", ssid).put("bssid", bssid)
    }

    private fun monitorStart(a: JSONObject): JSONObject {
        val id = a.optLong("id")
        synchronized(monitors) {
            monitors[id]?.let { connectivity.unregisterNetworkCallback(it) }
            val callback = object : ConnectivityManager.NetworkCallback() {}
            connectivity.registerDefaultNetworkCallback(callback)
            monitors[id] = callback
        }
        return JSONObject().put("started", true)
    }

    private fun monitorStop(a: JSONObject): JSONObject {
        synchronized(monitors) {
            val id = a.optLong("id", Long.MIN_VALUE)
            val entries = if (id == Long.MIN_VALUE) monitors.toMap() else listOfNotNull(monitors[id]?.let { id to it }).toMap()
            entries.forEach { (key, cb) -> runCatching { connectivity.unregisterNetworkCallback(cb) }; monitors.remove(key) }
        }
        return JSONObject().put("stopped", true)
    }

    private fun monitorPoll(a: JSONObject): JSONObject {
        val network = physicalNetwork(connectivity) ?: return JSONObject()
        val props = connectivity.getLinkProperties(network) ?: return JSONObject()
        val caps = connectivity.getNetworkCapabilities(network) ?: return JSONObject()
        val ni = props.interfaceName?.let(NetworkInterface::getByName)
        return JSONObject().put("interfaceName", props.interfaceName ?: "").put("interfaceIndex", ni?.index ?: 0)
            .put("expensive", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            .put("constrained", false).put("networkPath", "")
    }

    private fun sendNotification(a: JSONObject): JSONObject {
        val manager = context.getSystemService(android.app.NotificationManager::class.java)
        val channel = "lxbox.core"
        if (Build.VERSION.SDK_INT >= 26 && manager.getNotificationChannel(channel) == null) {
            manager.createNotificationChannel(android.app.NotificationChannel(channel, "LxBox", android.app.NotificationManager.IMPORTANCE_DEFAULT))
        }
        val id = a.optString("Identifier", a.optString("identifier")).hashCode()
        val title = a.optString("Title", a.optString("title", "LxBox"))
        val text = listOf(a.optString("Subtitle", a.optString("subtitle")), a.optString("Body", a.optString("body")))
            .filter { it.isNotBlank() }.joinToString("\n")
        val notification = androidx.core.app.NotificationCompat.Builder(context, channel)
            .setSmallIcon(android.R.drawable.stat_sys_warning).setContentTitle(title).setContentText(text)
            .setStyle(androidx.core.app.NotificationCompat.BigTextStyle().bigText(text)).setAutoCancel(true).build()
        manager.notify(id, notification)
        return JSONObject().put("sent", true).put("id", id)
    }

    private fun cancelNotification(a: JSONObject): JSONObject {
        val id = a.optString("identifier").hashCode()
        context.getSystemService(android.app.NotificationManager::class.java).cancel(id)
        return JSONObject().put("cancelled", true)
    }

    private fun emit(action: String, payload: JSONObject): JSONObject {
        val data = JSONObject().put("type", payload.optString("type")).put("data", payload.opt("data") ?: JSONObject.NULL)
        context.sendBroadcast(Intent(action).setPackage(context.packageName).putExtra("payload", data.toString()))
        return JSONObject().put("emitted", true)
    }

    private fun safImport(args: JSONObject): CompletableFuture<JSONArray> {
        val activity = MainActivity.current ?: error("SAF import requires a foreground Activity")
        val mimeTypes = args.optJSONArray("mime_types").strings().ifEmpty { listOf("*/*") }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(if (mimeTypes.size == 1) mimeTypes.first() else "*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes.toTypedArray())
            .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, args.optBoolean("allow_multiple"))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        return activity.requestSaf(intent) { result ->
            val out = JSONArray()
            val uris = selectedUris(result.data)
            for (uri in uris) {
                persistReadPermission(result.data, uri)
                val maxBytes = args.optLong("max_bytes", MAX_PICK_BYTES).coerceIn(1, MAX_PICK_BYTES)
                val bytes = readUri(uri, maxBytes)
                val name = queryName(uri) ?: uri.lastPathSegment ?: "file"
                val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
                out.put(JSONObject().put("kind", "file").put("name", name).put("mime", mime)
                    .put("uri", uri.toString()).put("bytes", Base64.encodeToString(bytes, Base64.NO_WRAP)))
            }
            out
        }
    }

    private fun filePick(args: JSONObject): CompletableFuture<Any> {
        val activity = MainActivity.current ?: error("file picking requires a foreground Activity")
        val mimeTypes = args.optJSONArray("mimeTypes").strings().ifEmpty { listOf("*/*") }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType(if (mimeTypes.size == 1) mimeTypes.first() else "*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes.toTypedArray())
            .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, args.optBoolean("allowMultiple"))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        return activity.requestSaf(intent) { result ->
            val uris = selectedUris(result.data)
            val out = JSONArray()
            for (uri in uris) {
                persistReadPermission(result.data, uri)
                val metadata = JSONObject().put("uri", uri.toString())
                    .put("name", queryName(uri) ?: uri.lastPathSegment.orEmpty())
                    .put("mime", context.contentResolver.getType(uri) ?: "application/octet-stream")
                    .put("size", querySize(uri))
                if (!args.optBoolean("metadataOnly", false)) {
                    val maxBytes = args.optLong("maxBytes", MAX_PICK_BYTES).coerceIn(1, MAX_PICK_BYTES)
                    metadata.put("text", readUri(uri, maxBytes).toString(Charsets.UTF_8))
                }
                out.put(metadata)
            }
            if (args.optBoolean("allowMultiple")) out else out.optJSONObject(0) ?: error("file picker was cancelled")
        }
    }

    private fun fileRead(args: JSONObject): JSONObject {
        val raw = args.getString("uri")
        val uri = android.net.Uri.parse(raw)
        val maxBytes = args.optLong("maxBytes", MAX_PICK_BYTES).coerceIn(1, MAX_PICK_BYTES)
        val bytes = readUri(uri, maxBytes)
        return JSONObject().put("uri", raw).put("text", bytes.toString(Charsets.UTF_8))
            .put("body", Base64.encodeToString(bytes, Base64.NO_WRAP))
            .put("data", Base64.encodeToString(bytes, Base64.NO_WRAP))
            .put("headers", JSONObject().put("content-type", context.contentResolver.getType(uri) ?: "application/octet-stream"))
    }

    private fun fileOpenRead(args: JSONObject): JSONObject {
        val raw = args.getString("uri")
        val uri = android.net.Uri.parse(raw)
        val input = openReadStream(uri)
        val size = querySize(uri)
        val handle = java.util.UUID.randomUUID().toString()
        streams[handle] = StreamEntry(input = input)
        return JSONObject().put("handle", handle).put("size", size)
            .put("name", queryName(uri) ?: uri.lastPathSegment.orEmpty())
            .put("mime", context.contentResolver.getType(uri) ?: "application/octet-stream")
    }

    private fun fileReadChunk(args: JSONObject): JSONObject {
        val handle = args.getString("handle")
        val maxBytes = args.optInt("maxBytes", 65536)
        require(maxBytes in 1..MAX_CHUNK_BYTES) { "file.readChunk maxBytes must be 1..$MAX_CHUNK_BYTES" }
        val entry = streams[handle] ?: error("unknown file stream handle")
        val buffer = ByteArray(maxBytes)
        val count = synchronized(entry) { entry.input?.read(buffer) ?: error("stream is not readable") }
        if (count < 0) return JSONObject().put("data", "").put("eof", true)
        return JSONObject().put("data", Base64.encodeToString(buffer, 0, count, Base64.NO_WRAP)).put("eof", false)
    }

    private fun fileCreate(args: JSONObject): CompletableFuture<JSONObject> {
        val activity = MainActivity.current ?: error("file creation requires a foreground Activity")
        val name = args.optString("suggestedName", "export")
        val mime = args.optString("mime", "application/octet-stream")
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType(mime).putExtra(Intent.EXTRA_TITLE, name)
            .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return activity.requestSaf(intent) { result ->
            val uri = result.data?.data ?: error("file creation was cancelled")
            val output = context.contentResolver.openOutputStream(uri, "w") ?: error("cannot open output document $uri")
            val handle = java.util.UUID.randomUUID().toString()
            streams[handle] = StreamEntry(output = output, uri = uri)
            JSONObject().put("handle", handle).put("uri", uri.toString()).put("name", queryName(uri) ?: name).put("mime", context.contentResolver.getType(uri) ?: mime)
        }
    }

    private fun fileWriteChunk(args: JSONObject): JSONObject {
        val handle = args.getString("handle")
        val data = Base64.decode(args.getString("data"), Base64.DEFAULT)
        require(data.size <= MAX_CHUNK_BYTES) { "file.writeChunk data exceeds $MAX_CHUNK_BYTES bytes" }
        val entry = streams[handle] ?: error("unknown file stream handle")
        synchronized(entry) { entry.output?.write(data) ?: error("stream is not writable"); entry.output?.flush() }
        return JSONObject().put("written", data.size)
    }

    private fun fileClose(args: JSONObject): JSONObject {
        val handle = args.getString("handle")
        val entry = streams.remove(handle) ?: error("unknown file stream handle")
        val commit = args.optBoolean("commit", true)
        synchronized(entry) {
            entry.input?.close()
            entry.output?.flush()
            entry.output?.close()
        }
        if (!commit && entry.uri != null) {
            runCatching { context.contentResolver.delete(entry.uri, null, null) }
                .onFailure { throw IllegalStateException("could not discard incomplete document", it) }
        }
        return JSONObject().put("closed", true).put("committed", commit)
    }

    private fun openReadStream(uri: android.net.Uri): InputStream = when (uri.scheme?.lowercase()) {
        "content" -> context.contentResolver.openInputStream(uri)
        "file" -> {
            val path = uri.path ?: error("file URI has no path")
            val file = File(path).canonicalFile
            val root = context.filesDir.canonicalFile
            require(file.path == root.path || file.path.startsWith(root.path + File.separator)) { "file URI must be inside the app files directory" }
            file.inputStream()
        }
        else -> throw IllegalArgumentException("unsupported document URI scheme: ${uri.scheme}")
    } ?: error("could not open document $uri")

    private fun querySize(uri: android.net.Uri): Long {
        if (uri.scheme == "file") return File(uri.path ?: error("file URI has no path")).length()
        return runCatching {
            context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)?.use {
                if (it.moveToFirst() && !it.isNull(0)) it.getLong(0) else -1L
            } ?: -1L
        }.getOrDefault(-1L)
    }

    fun closeAllStreams() {
        streams.entries.toList().forEach { (handle, entry) ->
            if (streams.remove(handle, entry)) synchronized(entry) { entry.input?.close(); entry.output?.close() }
        }
    }

    private fun selectedUris(data: Intent?): List<android.net.Uri> = buildList {
        data?.data?.let(::add)
        data?.clipData?.let { clip -> for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let(::add) }
    }.distinct()

    private fun persistReadPermission(data: Intent?, uri: android.net.Uri) {
        val granted = (data?.flags ?: 0) and Intent.FLAG_GRANT_READ_URI_PERMISSION
        if (granted == 0) return
        try {
            context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (e: SecurityException) {
            Log.w(TAG, "provider did not grant persistable URI permission for $uri", e)
        }
    }

    private fun readUri(uri: android.net.Uri, maxBytes: Long): ByteArray {
        val stream = when (uri.scheme?.lowercase()) {
            "content" -> context.contentResolver.openInputStream(uri)
            "file" -> uri.path?.let { File(it).inputStream() }
            else -> throw IllegalArgumentException("unsupported document URI scheme: ${uri.scheme}")
        } ?: error("could not open document $uri")
        return stream.use { input ->
            val bytes = input.readNBytes((maxBytes + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            require(bytes.size.toLong() <= maxBytes) { "document exceeds $maxBytes byte limit" }
            bytes
        }
    }

    private fun lanPost(a: JSONObject): JSONObject {
        val host = a.getString("host")
        val port = a.getInt("port")
        require(port in 1..65535) { "invalid LAN port" }
        val path = a.optString("path", "/transfer").ifBlank { "/transfer" }
        val body = Base64.decode(a.getString("body"), Base64.DEFAULT)
        val connectTimeout = a.optInt("connectTimeoutMs", 5000).coerceIn(1, 120_000)
        val readTimeout = a.optInt("readTimeoutMs", 60_000).coerceIn(1, 120_000)
        val target = InetAddress.getByName(host)
        val network = pickLanNetwork(target) ?: return JSONObject().put("outcome", "no_network")
        return try {
            network.socketFactory.createSocket().use { socket ->
                socket.connect(InetSocketAddress(host, port), connectTimeout)
                socket.soTimeout = readTimeout
                val head = "POST $path HTTP/1.1\r\nHost: $host:$port\r\nContent-Type: application/json\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().use { out -> out.write(head.toByteArray(Charsets.US_ASCII)); out.write(body); out.flush() }
                val bytes = ByteArrayOutputStream()
                val chunk = ByteArray(8192)
                val input = socket.getInputStream()
                while (bytes.size() < MAX_LAN_RESPONSE) {
                    val n = input.read(chunk)
                    if (n < 0) break
                    bytes.write(chunk, 0, n.coerceAtMost(MAX_LAN_RESPONSE - bytes.size()))
                }
                val text = bytes.toString(Charsets.UTF_8.name())
                val status = text.substringBefore("\r\n").split(' ').getOrNull(1)?.toIntOrNull()
                    ?: return JSONObject().put("outcome", "unreachable").put("detail", "bad response")
                JSONObject().put("outcome", "response").put("status", status)
                    .put("body", text.substringAfter("\r\n\r\n", "")).put("detail", "")
            }
        } catch (e: ConnectException) {
            if (e.message?.contains("REFUSED", true) == true) JSONObject().put("outcome", "refused")
            else JSONObject().put("outcome", "unreachable").put("detail", e.message ?: "connect failed")
        } catch (e: SocketTimeoutException) {
            JSONObject().put("outcome", "unreachable").put("detail", "timeout")
        } catch (e: IOException) {
            JSONObject().put("outcome", "unreachable").put("detail", e.message ?: "I/O failure")
        }
    }

    private fun pickLanNetwork(target: InetAddress): Network? {
        val candidates = connectivity.allNetworks.filter { network ->
            val caps = connectivity.getNetworkCapabilities(network) ?: return@filter false
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
        }
        return candidates.firstOrNull { network ->
            connectivity.getLinkProperties(network)?.linkAddresses?.any { link ->
                sameSubnet(link.address, target, link.prefixLength)
            } == true
        } ?: candidates.firstOrNull()
    }

    private fun sameSubnet(a: InetAddress, b: InetAddress, prefix: Int): Boolean {
        val left = a.address
        val right = b.address
        if (left.size != right.size) return false
        var bits = prefix
        for (i in left.indices) {
            if (bits <= 0) return true
            val mask = if (bits >= 8) 0xff else (0xff shl (8 - bits)) and 0xff
            if ((left[i].toInt() and mask) != (right[i].toInt() and mask)) return false
            bits -= 8
        }
        return true
    }

    private fun appsList(): JSONArray = JSONArray().also { out ->
        context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA).forEach { out.put(appInfoJson(it)) }
    }

    private fun appInfo(a: JSONObject): JSONObject {
        val packageName = a.getString("packageName")
        return try { appInfoJson(context.packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA)) }
        catch (_: PackageManager.NameNotFoundException) { JSONObject().put("packageName", packageName).put("notFound", true) }
    }

    private fun appInfoJson(info: ApplicationInfo): JSONObject {
        val pm = context.packageManager
        val packageInfo = runCatching { pm.getPackageInfo(info.packageName, 0) }.getOrNull()
        return JSONObject().put("packageName", info.packageName)
            .put("label", pm.getApplicationLabel(info).toString())
            .put("system", (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0)
            .put("uid", info.uid)
            .put("versionName", packageInfo?.versionName ?: "")
            .put("versionCode", if (Build.VERSION.SDK_INT >= 28) packageInfo?.longVersionCode ?: 0L else @Suppress("DEPRECATION") packageInfo?.versionCode ?: 0)
    }

    private fun appIcon(a: JSONObject): JSONObject {
        val packageName = a.getString("packageName")
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        val drawable = context.packageManager.getApplicationIcon(info)
        val width = maxOf(drawable.intrinsicWidth, 1)
        val height = maxOf(drawable.intrinsicHeight, 1)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        Canvas(bitmap).also { canvas -> drawable.setBounds(0, 0, canvas.width, canvas.height); drawable.draw(canvas) }
        val bytes = ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
        bitmap.recycle()
        return JSONObject().put("data", Base64.encodeToString(bytes, Base64.NO_WRAP)).put("mime", "image/png")
    }

    private fun openConnectStart(args: JSONObject): JSONObject {
        val tag = args.getString("tag")
        val challengeId = args.getString("challenge_id")
        val port = args.optInt("port", 8020)
        require(port in 1..65535) { "invalid OpenConnect callback port" }
        val prefixes = args.optJSONArray("prefixes").strings()
        synchronized(callbackLock) {
            openConnect?.takeIf { it.tag == tag && it.challengeId == challengeId }?.let {
                return JSONObject().put("listening", true)
            }
            openConnect?.close()
            val server = OpenConnectCallbackServer(tag, challengeId, port, prefixes) { url ->
                HostWorkers.executor.execute {
                    try {
                        NativeBridge.appCall("core.call", JSONObject().put("method", "ccSubmitOpenConnectBrowser")
                            .put("args", JSONObject().put("tag", tag).put("challenge_id", challengeId).put("url", url)))
                    } catch (t: Throwable) {
                        Log.e(TAG, "OpenConnect browser callback submit failed", t)
                    }
                }
            }
            val error = server.start()
            if (error != null) throw IllegalStateException(error)
            openConnect = server
        }
        return JSONObject().put("listening", true).put("port", port)
    }

    private fun openConnectStop(): JSONObject {
        synchronized(callbackLock) {
            openConnect?.close()
            openConnect = null
        }
        return JSONObject().put("stopped", true)
    }

    private fun safExport(args: JSONObject): CompletableFuture<JSONObject> {
        val activity = MainActivity.current ?: error("SAF export requires a foreground Activity")
        val payload = args.getJSONObject("payload")
        val name = payload.optString("name", "export")
        val mime = payload.optString("mime", "application/octet-stream")
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(mime).putExtra(Intent.EXTRA_TITLE, name)
        return activity.requestSaf(intent) { result ->
            val uri = result.data?.data ?: error("no export destination selected")
            val encoded = payload.optString("bytes")
            val bytes = if (encoded.isNotEmpty()) Base64.decode(encoded, Base64.DEFAULT) else payload.optString("text").toByteArray(Charsets.UTF_8)
            context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: error("cannot open export destination $uri")
            JSONObject().put("uri", uri.toString()).put("name", queryName(uri) ?: name).put("mime", context.contentResolver.getType(uri) ?: mime)
        }
    }

    private fun queryName(uri: android.net.Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        }
    }.getOrNull()

    private fun clipboardGet(): JSONObject {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = manager.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
        return JSONObject().put("text", text)
    }

    private fun clipboardSet(a: JSONObject): JSONObject {
        val text = a.getString("text")
        (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("LxBox", text))
        return JSONObject().put("set", true)
    }

    private fun permissionRequest(a: JSONObject): JSONObject {
        val activity = MainActivity.current ?: error("permission prompts require a foreground Activity")
        activity.requestPermission(a.getString("permission"))
        return JSONObject().put("requested", true)
    }

    private fun isForeground(): Boolean = MainActivity.current?.let { !it.isFinishing && it.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED) } == true

    private fun hasPermission(name: String): Boolean = ContextCompat.checkSelfPermission(context, name) == PackageManager.PERMISSION_GRANTED

    private fun nativePrefsGet(a: JSONObject): JSONObject {
        val p = LxBoxApplication.prefs
        val key = a.getString("key")
        val value = when {
            p.contains(key) -> p.all[key]
            else -> JSONObject.NULL
        }
        return JSONObject().put("key", key).put("value", value)
    }

    private fun nativePrefsApply(a: JSONObject): JSONObject {
        val editor = LxBoxApplication.prefs.edit()
        val native = a.optJSONObject("native_prefs")
        val vars = a.optJSONObject("vars")
        var changed = 0
        fun applyObject(value: JSONObject?) {
            if (value == null) return
            for (key in value.keys()) {
                val item = value.opt(key)
                when (item) {
                    JSONObject.NULL, null -> editor.remove(key)
                    is Boolean -> editor.putBoolean(key, item)
                    is Number -> editor.putLong(key, item.toLong())
                    is JSONArray -> editor.putStringSet(key, item.strings().toSet())
                    else -> editor.putString(key, item.toString())
                }
                changed++
            }
        }
        applyObject(native)
        applyObject(vars)
        check(editor.commit()) { "could not apply native preferences" }
        val automationEnabled = vars?.optBoolean("automation_receive_enabled", LxBoxApplication.prefs.getBoolean("automation_receive_enabled", false))
            ?: LxBoxApplication.prefs.getBoolean("automation_receive_enabled", false)
        setAutomationReceiverEnabled(automationEnabled)
        if (vars?.has("appfunctions_enabled") == true) setAppFunctionsEnabled(vars.optBoolean("appfunctions_enabled"))
        return JSONObject().put("applied", changed)
    }

    private fun setAutomationReceiverEnabled(enabled: Boolean) {
        val component = android.content.ComponentName(context, ExternalCommandReceiver::class.java)
        context.packageManager.setComponentEnabledSetting(
            component,
            if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP,
        )
    }

    private fun setAppFunctionsEnabled(enabled: Boolean) {
        LxBoxApplication.prefs.edit().putBoolean("appfunctions_enabled", enabled).commit()
        if (Build.VERSION.SDK_INT >= 36) {
            appFunctionsScope.launch {
                runCatching {
                    val manager = androidx.appfunctions.AppFunctionManager.getInstance(context)
                        ?: return@runCatching
                    val state = if (enabled) androidx.appfunctions.AppFunctionManager.APP_FUNCTION_STATE_ENABLED
                        else androidx.appfunctions.AppFunctionManager.APP_FUNCTION_STATE_DISABLED
                    listOf("com.leadaxe.lxbox.android.LxBoxAppFunctions#startVpn", "com.leadaxe.lxbox.android.LxBoxAppFunctions#stopVpn", "com.leadaxe.lxbox.android.LxBoxAppFunctions#getVpnStatus")
                        .forEach { manager.setAppFunctionEnabled(it, state) }
                }.onFailure { Log.w(TAG, "could not update AppFunctions system state", it) }
            }
        }
    }

    private fun nativePrefsSet(a: JSONObject): JSONObject {
        val key = a.getString("key")
        val value = a.opt("value")
        val editor = LxBoxApplication.prefs.edit()
        when (value) {
            JSONObject.NULL, null -> editor.remove(key)
            is Boolean -> editor.putBoolean(key, value)
            is Number -> editor.putLong(key, value.toLong())
            else -> editor.putString(key, value.toString())
        }
        check(editor.commit()) { "could not persist native preference $key" }
        return JSONObject().put("saved", true)
    }

    private fun JSONArray?.strings(): List<String> = if (this == null) emptyList() else (0 until length()).mapNotNull { optString(it).takeIf(String::isNotBlank) }
    private fun JSONArray?.nonEmptyStrings() = strings()

    private fun addPrefixes(values: JSONArray?, add: (String, Int) -> Unit) {
        values.strings().forEach { raw ->
            val slash = raw.lastIndexOf('/')
            require(slash > 0) { "invalid interface prefix: $raw" }
            add(raw.substring(0, slash), raw.substring(slash + 1).toInt())
        }
    }

    companion object {
        private const val TAG = "LxBoxHost"
        private const val DNS_TIMEOUT_MS = 10_000L
        @Volatile internal var current: Host? = null
        val instanceOrNull: Host? get() = current
        private const val MAX_PICK_BYTES = 16L * 1024L * 1024L
        private const val MAX_CHUNK_BYTES = 65_536
        private const val MAX_LAN_RESPONSE = 65_536
    }
}

internal object HostWorkers {
    val executor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "lxbox-service").apply { isDaemon = true } }
    val safExecutor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "lxbox-saf-io").apply { isDaemon = true } }
    val dnsExecutor: ExecutorService = Executors.newCachedThreadPool { r -> Thread(r, "lxbox-dns").apply { isDaemon = true } }
    val safIds = AtomicInteger(4000)
}

internal fun JSONArray?.strings(): List<String> = if (this == null) emptyList() else (0 until length()).mapNotNull { optString(it).takeIf(String::isNotBlank) }
