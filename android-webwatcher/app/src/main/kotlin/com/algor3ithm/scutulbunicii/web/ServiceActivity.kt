package com.algor3ithm.scutulbunicii.web

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebView
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout

/**
 * One service in a foreground WebView (desktop user agent, persistent cookies and DOM storage). The reader's in-page
 * banner shows the warning here exactly as on the desktop. While this screen is open, the background WebView of the same
 * service is closed (two sessions of one site would clash).
 */
class ServiceActivity : Activity() {
    private var web: WebView? = null
    private var service: Service? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val svc = Services.byName(this, intent.getStringExtra(EXTRA))
        if (svc == null) { finish(); return }
        service = svc
        val prefs = Prefs(this)

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.WHITE) }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#0B1F4B"))
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }
        fun bt(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label; textSize = 18f; isAllCaps = false
            setTextColor(Color.parseColor("#0B1F4B")); setBackgroundColor(Color.parseColor("#FFD54F"))
            minHeight = dp(56); minimumHeight = dp(56)
            setOnClickListener { onClick() }
        }
        bar.addView(bt("Înapoi") { finish() }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(8) })
        bar.addView(bt("Gata, sunt conectat") {
            prefs.setConnected(svc.name, true)
            finish()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 2f))
        root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        val v = ServiceWebView.create(this, svc, foreground = true, pollMs = prefs.pollSeconds * 1000L) { recreate() }
        web = v
        root.addView(FrameLayout(this).apply { addView(v, FrameLayout.LayoutParams(-1, -1, Gravity.TOP)) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        if (savedInstanceState != null) v.restoreState(savedInstanceState) else v.loadUrl(svc.url)
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density + 0.5f).toInt()

    override fun onStart() {
        super.onStart()
        service?.let { WatchService.suspend(it.name) }
    }

    override fun onPause() {
        super.onPause()
        web?.onPause()
        CookieManager.getInstance().flush()
    }

    override fun onResume() {
        super.onResume()
        web?.onResume()
    }

    override fun onStop() {
        super.onStop()
        service?.let { WatchService.resume(it.name) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web?.saveState(outState)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else super.onBackPressed()
    }

    override fun onDestroy() {
        web?.let { (it.parent as? ViewGroup)?.removeView(it); it.destroy() }
        web = null
        super.onDestroy()
    }

    companion object {
        const val EXTRA = "service"
    }
}
