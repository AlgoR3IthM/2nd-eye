package com.algor3ithm.scutulbunicii.web

import android.app.Notification
import android.app.PendingIntent
import android.app.Service as AndroidService
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.webkit.WebView

/**
 * Foreground service (type specialUse) that keeps off-screen WebViews for the connected services. The readers run their
 * list-preview path on their own timer (unread rows only, never clicks); this service keeps the WebViews alive.
 */
class WatchService : AndroidService() {
    private val main = Handler(Looper.getMainLooper())
    private val views = HashMap<String, WebView>()
    private var wake: PowerManager.WakeLock? = null
    private var running = false

    private val keepAlive = object : Runnable {
        override fun run() {
            try { wake?.acquire(WAKE_MS) } catch (_: Exception) { }    // renewed every minute, expires by itself if we die
            for ((name, wv) in views.toMap()) {
                val svc = Services.byName(this@WatchService, name) ?: continue
                val host = try { java.net.URI(wv.url ?: "").host } catch (_: Exception) { null }
                if (wv.url == null) { wv.loadUrl(svc.url); continue }
                if (!svc.allowsHost(host)) continue                  // sign-in page: nothing to keep alive
                // reader gone (page reloaded or crashed): reload so onPageFinished injects it again
                wv.evaluateJavascript("typeof window.__SB") { r -> if (r != "\"object\"") wv.reload() }
            }
            main.postDelayed(this, KEEPALIVE_MS)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        AlertDispatcher.ensureChannels(this)
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = Notification.Builder(this, AlertDispatcher.CHANNEL_WATCH)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("2nd Eye vă păzește mesajele")
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(open)
            .build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIF_ID, n)

        if (!running) {
            running = true
            wake = getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "scutul:watch").apply { setReferenceCounted(false); acquire(WAKE_MS) }
            main.postDelayed(keepAlive, KEEPALIVE_MS)
        }
        sync()
        return START_STICKY
    }

    /** Make the set of live WebViews match: connected services that are not open in the service screen. */
    private fun sync() {
        val prefs = Prefs(this)
        if (!prefs.background) { stopSelf(); return }
        val wanted = Services.all(this).filter { prefs.connected(it.name) && it.name !in suspended }
        for (name in views.keys.toList()) if (wanted.none { it.name == name }) drop(name)
        var i = 0
        for (svc in wanted) {
            if (views.containsKey(svc.name)) continue
            main.postDelayed({ if (running && !views.containsKey(svc.name) && svc.name !in suspended) create(svc) }, 4000L * i++)
        }
    }

    private fun create(svc: Service) {
        val prefs = Prefs(this)
        val v = ServiceWebView.create(this, svc, foreground = false, pollMs = prefs.pollSeconds * 1000L) {
            // renderer killed by Android: rebuild this service's WebView
            drop(svc.name)
            main.postDelayed({ if (running && svc.name !in suspended) create(svc) }, 5000)
        }
        val dm = resources.displayMetrics
        ServiceWebView.layoutOffscreen(v, dm.widthPixels, dm.heightPixels)
        views[svc.name] = v
        v.loadUrl(svc.url)
    }

    private fun drop(name: String) {
        views.remove(name)?.let { v ->
            try { v.stopLoading(); v.loadUrl("about:blank"); v.destroy() } catch (_: Exception) { }
        }
    }

    override fun onDestroy() {
        running = false
        main.removeCallbacksAndMessages(null)
        for (n in views.keys.toList()) drop(n)
        try { wake?.takeIf { it.isHeld }?.release() } catch (_: Exception) { }
        instance = null
        super.onDestroy()
    }

    companion object {
        private const val NOTIF_ID = 1
        private const val KEEPALIVE_MS = 60_000L
        private const val WAKE_MS = 10 * 60_000L
        @Volatile private var instance: WatchService? = null
        private val suspended = HashSet<String>()

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, WatchService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, WatchService::class.java))
        }

        /** The service screen is open for [name]: drop its background WebView (two sessions of one site clash, e.g. WhatsApp Web). */
        fun suspend(name: String) {
            suspended.add(name)
            instance?.let { s -> s.main.post { s.drop(name) } }
        }

        fun resume(name: String) {
            suspended.remove(name)
            instance?.let { s -> s.main.post { s.sync() } }
        }

        /** Re-read settings (connected services, background switch). */
        fun refresh(ctx: Context) {
            if (instance != null) start(ctx)
        }
    }
}
