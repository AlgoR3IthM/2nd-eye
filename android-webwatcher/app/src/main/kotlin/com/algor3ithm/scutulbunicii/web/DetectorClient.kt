package com.algor3ithm.scutulbunicii.web

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * HTTP client for the detector API on the laptop. Message text goes ONLY to the configured address.
 * Blocking: always call from the [io] executor, never from the main thread. Nothing here logs or stores text.
 */
object DetectorClient {
    val io = Executors.newFixedThreadPool(2)

    private const val CONNECT_MS = 5_000
    private const val ANALYZE_READ_MS = 90_000
    private const val HEALTH_READ_MS = 6_000

    /** Returns a clean base URL (no trailing slash) or null when the address is unusable or not allowed. */
    fun normalize(raw: String): String? {
        var s = raw.trim().trimEnd('/')
        if (s.isEmpty()) return null
        if (!s.contains("://")) s = "http://$s"
        val u = try { URL(s) } catch (_: Exception) { return null }
        val host = u.host ?: return null
        if (host.isEmpty()) return null
        return when (u.protocol) {
            "https" -> s
            "http" -> if (isLocalNetwork(host)) s else null   // cleartext only inside the local network
            else -> null
        }
    }

    /** Loopback, link-local, private IPv4 ranges, CGNAT/Tailscale, ".local" names and single-label LAN host names. */
    private fun isLocalNetwork(host: String): Boolean {
        val h = host.lowercase()
        if (h == "localhost" || h.endsWith(".local")) return true
        val m = Regex("""(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})""").matchEntire(h) ?: return !h.contains('.')
        val a = m.groupValues.drop(1).map { it.toInt() }
        return a[0] == 10 || a[0] == 127 || (a[0] == 192 && a[1] == 168) || (a[0] == 172 && a[1] in 16..31) ||
            (a[0] == 169 && a[1] == 254) || (a[0] == 100 && a[1] in 64..127)
    }

    private fun open(url: String, method: String, readMs: Int): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = CONNECT_MS
        c.readTimeout = readMs
        c.useCaches = false
        c.instanceFollowRedirects = false
        c.setRequestProperty("Accept", "application/json")
        return c
    }

    /** GET /api/health -> parsed JSON or null. */
    fun health(base: String): JSONObject? = try {
        val c = open("$base/api/health", "GET", HEALTH_READ_MS)
        try {
            if (c.responseCode != 200) null else JSONObject(c.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
        } finally { c.disconnect() }
    } catch (_: Exception) { null }

    /** POST /api/analyze[?trust_gate=true] with the scenario JSON -> parsed response or null on any failure. */
    fun analyze(base: String, scenario: JSONObject, trustGate: Boolean): JSONObject? = try {
        val c = open("$base/api/analyze" + if (trustGate) "?trust_gate=true" else "", "POST", ANALYZE_READ_MS)
        try {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            c.outputStream.use { it.write(scenario.toString().toByteArray(Charsets.UTF_8)) }
            if (c.responseCode != 200) null else JSONObject(c.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
        } finally { c.disconnect() }
    } catch (_: Exception) { null }
}
