package com.algor3ithm.scutulbunicii.web

import android.content.Context
import android.content.SharedPreferences

/** One messaging service. [name] and [url] come from the first line of its reader: `// @service name url`. */
data class Service(val name: String, val url: String, val label: String, val hosts: List<String>) {
    fun allowsHost(host: String?): Boolean {
        val h = host?.lowercase() ?: return false
        return hosts.any { h == it || h.endsWith(".$it") }
    }
}

object Services {
    private val LABELS = mapOf(
        "whatsapp" to "WhatsApp", "messenger" to "Messenger", "instagram" to "Instagram",
        "telegram" to "Telegram", "gmail" to "Gmail",
    )
    // Same host lists as the readers' own `hostnames` (the reader only activates on these hosts).
    private val HOSTS = mapOf(
        "whatsapp" to listOf("web.whatsapp.com"),
        "messenger" to listOf("messenger.com", "facebook.com"),
        "instagram" to listOf("instagram.com"),
        "telegram" to listOf("web.telegram.org"),
        "gmail" to listOf("mail.google.com"),
    )
    private val ORDER = listOf("whatsapp", "messenger", "instagram", "telegram", "gmail")
    private val HEADER = Regex("""//\s*@service\s+(\S+)\s+(\S+)""")

    @Volatile private var cache: List<Service>? = null

    fun all(ctx: Context): List<Service> {
        cache?.let { return it }
        val am = ctx.applicationContext.assets
        val found = ArrayList<Service>()
        for (f in am.list("readers").orEmpty().sorted()) {
            if (!f.endsWith(".js") || f == "common.js") continue
            val first = try {
                am.open("readers/$f").bufferedReader(Charsets.UTF_8).use { it.readLine() } ?: ""
            } catch (_: Exception) { "" }
            val m = HEADER.find(first) ?: continue
            val name = m.groupValues[1]
            val url = m.groupValues[2]
            val host = try { java.net.URI(url).host } catch (_: Exception) { null }
            found.add(Service(name, url, LABELS[name] ?: name.replaceFirstChar { it.uppercase() },
                HOSTS[name] ?: listOfNotNull(host)))
        }
        found.sortBy { val i = ORDER.indexOf(it.name); if (i < 0) 99 else i }
        cache = found
        return found
    }

    fun byName(ctx: Context, name: String?): Service? = all(ctx).firstOrNull { it.name == name }

    /** Script injected into a page: config, shim, common.js, this service's reader. Safe to inject twice. */
    fun script(ctx: Context, service: Service, banner: Boolean, pollMs: Long): String {
        val am = ctx.applicationContext.assets
        fun read(p: String) = am.open(p).bufferedReader(Charsets.UTF_8).use { it.readText() }
        val cfg = "window.__SB_CFG={banner:$banner,list:true,openStrangers:false,pollMs:$pollMs};"
        return "(function(){if(window.__SB)return;$cfg\n" + read("shim.js") + "\n" + read("readers/common.js") + "\n" +
            read("readers/${service.name}.js") + "\n})();"
    }
}

/** Settings and the trusted list. Only identifiers (numbers, addresses, names) are stored, never message text. */
class Prefs(ctx: Context) {
    private val sp: SharedPreferences = ctx.applicationContext.getSharedPreferences("scutul", Context.MODE_PRIVATE)

    var detector: String
        get() = sp.getString("detector", "") ?: ""
        set(v) { sp.edit().putString("detector", v).apply() }

    var background: Boolean
        get() = sp.getBoolean("background", false)
        set(v) { sp.edit().putBoolean("background", v).apply() }

    var pollSeconds: Int
        get() = sp.getInt("poll", 20)
        set(v) { sp.edit().putInt("poll", v).apply() }

    fun connected(service: String): Boolean = sp.getBoolean("connected_$service", false)
    fun setConnected(service: String, v: Boolean) { sp.edit().putBoolean("connected_$service", v).apply() }
}

class Trusted(ctx: Context) {
    private val sp: SharedPreferences = ctx.applicationContext.getSharedPreferences("trusted", Context.MODE_PRIVATE)

    private fun norm(s: String?): String = (s ?: "").trim().lowercase().replace(Regex("""[\s().\-]+"""), "")

    private fun keys(address: String?, name: String?): List<String> = listOf(norm(address), norm(name)).filter { it.isNotEmpty() }

    fun has(service: String, address: String?, name: String?): Boolean {
        val have = sp.getStringSet(service, emptySet()) ?: emptySet()
        return keys(address, name).any { it in have }
    }

    /** Stores the address when there is one, else the name (same rule as the desktop watcher). */
    fun add(service: String, address: String?, name: String?) {
        val k = keys(address, name).firstOrNull() ?: return
        synchronized(this) {
            val cur = HashSet(sp.getStringSet(service, emptySet()) ?: emptySet())
            if (cur.add(k)) sp.edit().putStringSet(service, cur).apply()
        }
    }
}
