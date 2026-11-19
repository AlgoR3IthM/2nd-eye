package com.algor3ithm.scutulbunicii.web

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Android replacement for Playwright's exposed bindings. The readers call window.__sbAnalyze(payload) and
 * window.__sbTrust(payload) (Promises, see assets/shim.js); this class answers through window.__sbResolve(id, json).
 * Message text is only forwarded to the configured detector address. Nothing is logged, cached on disk or sent elsewhere.
 */
class ReaderBridge(
    private val ctx: Context,
    private val service: Service,
    @Suppress("unused") private val foreground: Boolean,   // kept for symmetry with the page config
    private val webView: () -> WebView?,
) {
    private val main = Handler(Looper.getMainLooper())
    private val trusted = Trusted(ctx)
    private val prefs = Prefs(ctx)

    private fun answer(id: Int, json: String) {
        main.post {
            webView()?.evaluateJavascript("window.__sbResolve($id,${JSONObject.quote(json)})", null)
        }
    }

    @JavascriptInterface
    fun analyze(id: Int, payloadJson: String) {
        DetectorClient.io.execute {
            answer(id, try { doAnalyze(payloadJson).toString() } catch (_: Exception) { FAIL })
        }
    }

    @JavascriptInterface
    fun trust(id: Int, payloadJson: String) {
        // Only identifiers are stored. Ignored unless the page really is this service (see ServiceWebView.pageHostOk).
        val ok = try {
            val p = JSONObject(payloadJson)
            val s = p.optJSONObject("sender")
            if (pageHostOk) {
                trusted.add(service.name, s?.optString("address")?.takeIf { it != "null" }, s?.optString("name")?.takeIf { it != "null" })
                true
            } else false
        } catch (_: Exception) { false }
        answer(id, ok.toString())
    }

    private fun doAnalyze(payloadJson: String): JSONObject {
        val p = JSONObject(payloadJson)
        val sc = p.getJSONObject("scenario")
        val sender = sc.optJSONObject("sender") ?: JSONObject()
        val address = sender.optString("address", "").takeIf { it.isNotEmpty() && it != "null" }
        val name = sender.optString("name", "").takeIf { it.isNotEmpty() && it != "null" }
        val known = sc.optBoolean("known_contact", false) || trusted.has(service.name, address, name)
        sender.put("known_contact", known)
        sc.put("sender", sender).put("known_contact", known).put("id", service.name + "-android")

        val base = DetectorClient.normalize(prefs.detector) ?: return JSONObject(FAIL)
        val res = DetectorClient.analyze(base, sc, trustGate = known)   // known contact -> tripwire only
        if (res == null || !res.has("verdict")) return JSONObject(FAIL)

        val verdict = res.optString("verdict")
        val label = res.optJSONObject("label")?.optString("ro")
        val warning = res.optJSONObject("warning")?.optString("ro")
        if (verdict == "SCAM" || verdict == "SUSPICIOUS") {
            // stable per conversation state: hash of service + sender + verdict + scenario (a hash, never the text)
            val id = sha1(listOf(service.name, address ?: name ?: "", verdict, sc.toString()).joinToString("|")).take(16)
            AlertDispatcher.dispatch(
                ctx, Alert(service.name, name ?: address ?: "necunoscut", verdict, label.orEmpty(), warning.orEmpty(),
                    res.optInt("risk_score", 0), id)
            )
        }
        val slim = JSONObject()
            .put("verdict", verdict)
            .put("risk_score", res.opt("risk_score"))
            .put("first_alert", res.opt("first_alert"))
            .put("label", res.optJSONObject("label"))
            .put("warning", res.optJSONObject("warning"))
        return JSONObject().put("ok", true).put("known", known).put("result", slim)
    }

    private fun sha1(s: String): String =
        MessageDigest.getInstance("SHA-1").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    @Volatile internal var pageHostOk = false

    companion object {
        private const val FAIL = """{"ok":false}"""
    }
}

/** Builds the WebViews used by both the service screen and the background service. */
object ServiceWebView {
    /** Desktop Chrome user agent that keeps the real WebView's Chrome version (the sites check it). */
    fun desktopUserAgent(default: String): String {
        val major = Regex("""Chrome/(\d+)""").find(default)?.groupValues?.get(1) ?: "124"
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
            "Chrome/$major.0.0.0 Safari/537.36"
    }

    /** [onRenderGone] is called on the main thread when Android killed the renderer (the WebView must be recreated). */
    @SuppressLint("SetJavaScriptEnabled", "AddJavascriptInterface")
    fun create(
        ctx: Context, service: Service, foreground: Boolean, pollMs: Long, onRenderGone: (() -> Unit)? = null,
    ): WebView {
        var wv: WebView? = null
        val bridge = ReaderBridge(ctx, service, foreground) { wv }
        val v = WebView(ctx)
        wv = v
        with(v.settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            userAgentString = desktopUserAgent(userAgentString)
            useWideViewPort = false            // lay out at phone width so the warning banner stays readable
            loadWithOverviewMode = false
            setSupportZoom(true)
            builtInZoomControls = true
            displayZoomControls = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            allowFileAccess = false
            allowContentAccess = false
            mediaPlaybackRequiresUserGesture = true
            setGeolocationEnabled(false)
        }
        CookieManager.getInstance().apply {
            setAcceptCookie(true)
            setAcceptThirdPartyCookies(v, true)       // WhatsApp / Google sign-in flows need them
        }
        v.addJavascriptInterface(bridge, "__SBNative")
        v.webChromeClient = WebChromeClient()
        v.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                // https only: blocks intent:// , fb:// , market:// , http:// (apps / downgrade attempts)
                return request.url.scheme != "https"
            }

            override fun onPageFinished(view: WebView, url: String?) = inject(view, url)

            override fun doUpdateVisitedHistory(view: WebView, url: String?, isReload: Boolean) = inject(view, url)

            private fun inject(view: WebView, url: String?) {
                val host = try { java.net.URI(url ?: "").host } catch (_: Exception) { null }
                bridge.pageHostOk = service.allowsHost(host)
                if (!bridge.pageHostOk) return          // login pages on other hosts (e.g. accounts.google.com) stay untouched
                // After page load, and again on SPA navigation; the script skips itself when already present.
                // evaluateJavascript is not subject to the page's Content-Security-Policy.
                view.evaluateJavascript(Services.script(ctx, service, foreground, pollMs), null)
            }

            override fun onRenderProcessGone(view: WebView, detail: android.webkit.RenderProcessGoneDetail): Boolean {
                onRenderGone?.invoke()
                return true
            }
        }
        return v
    }

    /** Lets an unattached (off-screen) WebView lay out like a phone-sized page. */
    fun layoutOffscreen(v: WebView, widthPx: Int, heightPx: Int) {
        v.measure(
            android.view.View.MeasureSpec.makeMeasureSpec(widthPx, android.view.View.MeasureSpec.EXACTLY),
            android.view.View.MeasureSpec.makeMeasureSpec(heightPx, android.view.View.MeasureSpec.EXACTLY),
        )
        v.layout(0, 0, widthPx, heightPx)
    }
}
