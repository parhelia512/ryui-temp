package com.leadaxe.lxbox.android

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import androidx.core.content.ContextCompat
import dev.ryui.RyUIActivity
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicReference

class MainActivity : RyUIActivity() {
    private var finishAfterConsent = false
    private var pendingVpnAction = BoxVpnService.ACTION_START
    private var pendingVpnConfig = ""
    private var permissionRequestCode = 7100

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        current = this
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onDestroy() {
        if (current === this) current = null
        super.onDestroy()
    }

    private fun handleIntent(intent: Intent?) {
        when (intent?.getStringExtra(EXTRA_ACTION)) {
            ACTION_CONNECT -> {
                finishAfterConsent = intent.getBooleanExtra(EXTRA_FINISH, false)
                requestVpnStart(BoxVpnService.ACTION_START, "")
                intent.removeExtra(EXTRA_ACTION)
            }
            ACTION_DISCONNECT -> {
                NativeBridgeCall.stop()
                if (intent.getBooleanExtra(EXTRA_FINISH, false)) finish()
                intent.removeExtra(EXTRA_ACTION)
            }
            ACTION_TOGGLE -> {
                if (BoxVpnService.running) NativeBridgeCall.stop() else requestVpnStart(BoxVpnService.ACTION_START, "")
                if (intent.getBooleanExtra(EXTRA_FINISH, false)) finish()
                intent.removeExtra(EXTRA_ACTION)
            }
        }
    }

    private fun requestVpnStart(action: String, config: String) {
        pendingVpnAction = action
        pendingVpnConfig = config
        val consent = VpnService.prepare(this)
        if (consent == null) {
            startVpnService(action, config)
            return
        }
        try {
            startActivityForResult(consent, VPN_REQUEST_CODE)
        } catch (t: Throwable) {
            Log.e(TAG, "VPN consent could not be opened", t)
            if (finishAfterConsent) finish()
        }
    }

    private fun startVpnService(action: String, config: String) {
        val service = Intent(this, BoxVpnService::class.java).setAction(action)
            .putExtra(BoxVpnService.EXTRA_CONFIG, config)
        ContextCompat.startForegroundService(this, service)
        if (finishAfterConsent) finish()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) startVpnService(pendingVpnAction, pendingVpnConfig)
            else if (finishAfterConsent) finish()
            return
        }
        if (requestCode != SAF_REQUEST_CODE) return
        val pending = pendingSaf ?: return
        pendingSaf = null
        if (resultCode != Activity.RESULT_OK || data == null) {
            pending.future.completeExceptionally(CancellationException("SAF selection cancelled"))
            return
        }
        HostWorkers.safExecutor.execute {
            try {
                pending.future.complete(pending.transform(ActivityResult(resultCode, data)))
            } catch (t: Throwable) {
                pending.future.completeExceptionally(t)
            }
        }
    }

    fun requestPermission(permission: String) {
        runOnUiThread { requestPermissions(arrayOf(permission), permissionRequestCode++) }
    }

    fun <T> requestSaf(intent: Intent, transform: (ActivityResult) -> T): CompletableFuture<T> {
        val raw = CompletableFuture<Any?>()
        runOnUiThread {
            if (pendingSaf != null) {
                raw.completeExceptionally(IllegalStateException("another SAF request is already running"))
                return@runOnUiThread
            }
            pendingSaf = SafPending(raw) { result -> transform(result) }
            try {
                startActivityForResult(intent, SAF_REQUEST_CODE)
            } catch (t: Throwable) {
                pendingSaf = null
                raw.completeExceptionally(t)
            }
        }
        @Suppress("UNCHECKED_CAST")
        return raw.thenApply { it as T }
    }

    private data class SafPending(
        val future: CompletableFuture<Any?>,
        val transform: (ActivityResult) -> Any?,
    )
    private var pendingSaf: SafPending? = null

    data class ActivityResult(val resultCode: Int, val data: Intent?)

    companion object {
        private const val TAG = "LxBoxActivity"
        private const val VPN_REQUEST_CODE = 7200
        private const val SAF_REQUEST_CODE = 7201
        const val EXTRA_ACTION = "action"
        const val EXTRA_FINISH = "finish"
        const val ACTION_CONNECT = "connect"
        const val ACTION_DISCONNECT = "disconnect"
        const val ACTION_TOGGLE = "toggle"

        @Volatile var current: MainActivity? = null
            private set

        fun requestVpnConsent(context: Context, action: String, config: String): Boolean {
            val activity = current ?: return false
            activity.runOnUiThread { activity.requestVpnStart(action, config) }
            return true
        }
    }
}

private object NativeBridgeCall {
    fun stop() {
        HostWorkers.executor.execute {
            runCatching { NativeBridge.appCall("vpn.stop") }
                .onFailure { Log.e("LxBoxActivity", "native stop failed", it) }
        }
    }
}

class BoxVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        live = this
        createChannel()
        startForeground(NOTIFICATION_ID, notification("Starting"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        val config = intent?.getStringExtra(EXTRA_CONFIG).orEmpty()
        status = if (action == ACTION_STOP) "stopping" else "starting"
        HostWorkers.executor.execute { handle(action, config) }
        return START_STICKY
    }

    private fun handle(action: String, config: String) {
        when (action) {
            ACTION_STOP -> {
                runCatching { NativeBridge.appCall("service.stop") }
                    .onFailure { Log.e(TAG, "service stop failed", it) }
                closeTun()
                running = false
                status = "stopped"
                broadcastStatus("stopped")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            ACTION_START, ACTION_RELOAD -> {
                try {
                    val args = if (config.isBlank()) org.json.JSONObject() else org.json.JSONObject().put("config", config)
                    NativeBridge.appCall(if (action == ACTION_START) "service.start" else "service.reload", args)
                    running = true
                    status = "started"
                    broadcastStatus("running")
                } catch (t: Throwable) {
                    running = false
                    status = "error"
                    Log.e(TAG, "service $action failed", t)
                    broadcastStatus("error", t.message)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    fun newBuilder(): VpnService.Builder = Builder()

    fun replaceTun(next: ParcelFileDescriptor) {
        synchronized(this) {
            tun?.runCatching { close() }?.onFailure { Log.w(TAG, "old TUN close failed", it) }
            tun = next
        }
    }

    private fun closeTun() {
        synchronized(this) {
            tun?.runCatching { close() }
            tun = null
        }
    }

    override fun onRevoke() {
        HostWorkers.executor.execute { runCatching { NativeBridge.appCall("service.stop") } }
        super.onRevoke()
    }

    override fun onDestroy() {
        Host.instanceOrNull?.closeAllStreams()
        closeTun()
        if (live === this) live = null
        running = false
        status = "stopped"
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL, "LxBox VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun notification(text: String): Notification = androidx.core.app.NotificationCompat.Builder(this, CHANNEL)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle("LxBox")
        .setContentText(text)
        .setOngoing(true)
        .build()

    private fun broadcastStatus(state: String, error: String? = null) {
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, state).putExtra(EXTRA_ERROR, error))
    }

    companion object {
        private const val TAG = "LxBoxVpnService"
        private const val CHANNEL = "lxbox.vpn"
        private const val NOTIFICATION_ID = 42
        const val ACTION_START = "com.leadaxe.lxbox.ACTION_START"
        const val ACTION_RELOAD = "com.leadaxe.lxbox.ACTION_RELOAD"
        const val ACTION_STOP = "com.leadaxe.lxbox.ACTION_STOP"
        const val ACTION_STATUS = "com.leadaxe.lxbox.ACTION_STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_STATUS = "status"
        const val EXTRA_ERROR = "error"
        @Volatile var status: String = "stopped"
            private set
        @Volatile var live: BoxVpnService? = null
            private set
        @Volatile var running: Boolean = false
            private set
    }
}

class LxBoxTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (BoxVpnService.running) {
            HostWorkers.executor.execute { runCatching { NativeBridge.appCall("vpn.stop") } }
        } else if (VpnService.prepare(this) != null) {
            val intent = Intent(this, MainActivity::class.java).putExtra(MainActivity.EXTRA_ACTION, MainActivity.ACTION_CONNECT)
                .putExtra(MainActivity.EXTRA_FINISH, true).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 29) startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 0, intent, android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE))
            else @Suppress("DEPRECATION") run { startActivityAndCollapse(intent) }
        } else {
            HostWorkers.executor.execute { runCatching { NativeBridge.appCall("vpn.start") } }
        }
        updateTile()
    }

    private fun updateTile() {
        qsTile?.apply {
            state = if (BoxVpnService.running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            updateTile()
        }
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!LxBoxApplication.prefs.getBoolean("auto_start", false)) return
        if (VpnService.prepare(context) != null) return
        goAsync().let { pending ->
            HostWorkers.executor.execute {
                try { NativeBridge.appCall("vpn.start") }
                catch (t: Throwable) { Log.e("LxBoxBoot", "boot VPN start failed", t) }
                finally { pending.finish() }
            }
        }
    }
}

class ExternalCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val pending = goAsync()
        HostWorkers.executor.execute {
            try {
                when (action) {
                    "com.leadaxe.lxbox.START_VPN" -> NativeBridge.appCall("vpn.start")
                    "com.leadaxe.lxbox.STOP_VPN" -> NativeBridge.appCall("vpn.stop")
                    "com.leadaxe.lxbox.TOGGLE_VPN" -> NativeBridge.appCall("toggle-vpn")
                    "com.leadaxe.lxbox.SWITCH_NODE", "com.leadaxe.lxbox.SET_GROUP",
                    "com.leadaxe.lxbox.REBUILD_CONFIG", "com.leadaxe.lxbox.REFRESH_SUBS",
                    "com.leadaxe.lxbox.RESET_NETWORK", "com.leadaxe.lxbox.URLTEST_GROUP",
                    "com.leadaxe.lxbox.URLTEST_ALL" -> NativeBridge.appCall(
                        "automation.action",
                        org.json.JSONObject().put("action", action.substringAfterLast('.').lowercase())
                            .put("args", org.json.JSONObject().apply {
                                intent.extras?.keySet()?.forEach { put(it, intent.extras?.get(it) ?: org.json.JSONObject.NULL) }
                            }),
                    )
                }
            } catch (t: Throwable) { Log.e("LxBoxAutomation", "command failed: $action", t) }
            finally { pending.finish() }
        }
    }
}
