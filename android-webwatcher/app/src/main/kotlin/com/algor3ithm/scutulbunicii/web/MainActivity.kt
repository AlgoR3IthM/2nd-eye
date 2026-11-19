package com.algor3ithm.scutulbunicii.web

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/** Home screen: Romanian, large type (18 sp and up), high contrast. Built in code, no layout files, no libraries. */
class MainActivity : Activity() {
    private lateinit var prefs: Prefs
    private lateinit var address: EditText
    private lateinit var result: TextView
    private lateinit var bgSwitch: Switch
    private val hints = HashMap<String, TextView>()
    private var building = false

    private fun dp(v: Int) = (v * resources.displayMetrics.density + 0.5f).toInt()

    private fun text(s: String, sp: Float, color: Int = Color.BLACK, bold: Boolean = false) = TextView(this).apply {
        this.text = s
        textSize = sp
        setTextColor(color)
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun button(s: String) = Button(this).apply {
        text = s
        textSize = 22f
        isAllCaps = false
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.parseColor("#1A237E"))
        minHeight = dp(64)
        minimumHeight = dp(64)
    }

    private fun lp(top: Int = 0) = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        .apply { topMargin = dp(top) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        AlertDispatcher.ensureChannels(this)

        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0B1F4B"))
            setPadding(dp(20), dp(28), dp(20), dp(20))
            addView(text("2nd Eye", 32f, Color.WHITE, true))
            addView(text("de echipa AlgoR3IthM", 20f, Color.parseColor("#FFD54F"), true))
        }
        col.addView(header, lp())

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
        }
        col.addView(body, lp())

        body.addView(text("Serviciile dumneavoastră", 24f, Color.BLACK, true), lp())
        for (svc in Services.all(this)) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundColor(Color.parseColor("#EEF1F6"))
                setPadding(dp(16), dp(14), dp(16), dp(14))
            }
            card.addView(text(svc.label, 26f, Color.BLACK, true), lp())
            val hint = text("", 20f, Color.BLACK, true)
            hints[svc.name] = hint
            card.addView(hint, lp(2))
            val b = button("Conectare")
            b.setOnClickListener {
                prefs.detector = address.text.toString().trim()
                startActivity(Intent(this, ServiceActivity::class.java).putExtra(ServiceActivity.EXTRA, svc.name))
            }
            card.addView(b, lp(10))
            body.addView(card, lp(12))
        }

        body.addView(text("Adresa detectorului (laptopul)", 24f, Color.BLACK, true), lp(28))
        body.addView(text("Telefonul și laptopul trebuie să fie în aceeași rețea Wi-Fi.", 18f, Color.parseColor("#222222")), lp(4))
        address = EditText(this).apply {
            setText(prefs.detector)
            hint = "http://192.168.1.20:8000"
            textSize = 22f
            setTextColor(Color.BLACK)
            setHintTextColor(Color.parseColor("#555555"))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            minHeight = dp(60)
        }
        body.addView(address, lp(8))
        val test = button("Testează legătura")
        test.setOnClickListener { testConnection() }
        body.addView(test, lp(8))
        result = text("", 20f, Color.BLACK, true)
        body.addView(result, lp(8))

        bgSwitch = Switch(this).apply {
            text = "Păzește mesajele în fundal"
            textSize = 22f
            setTextColor(Color.BLACK)
            minHeight = dp(72)
            isChecked = prefs.background
        }
        building = false
        bgSwitch.setOnCheckedChangeListener { _, on -> if (!building) onBackground(on) }
        body.addView(bgSwitch, lp(28))
        body.addView(
            text("Cât timp este pornit, în bara de sus apare o notificare discretă. Textul mesajelor merge doar la detectorul de pe laptopul dumneavoastră.",
                18f, Color.parseColor("#222222")), lp(6)
        )

        setContentView(ScrollView(this).apply {
            setBackgroundColor(Color.WHITE)
            isFillViewport = true
            addView(col)
        })
    }

    override fun onResume() {
        super.onResume()
        for (svc in Services.all(this)) {
            hints[svc.name]?.apply {
                val on = prefs.connected(svc.name)
                text = if (on) "Conectat" else "Neconectat"
                setTextColor(Color.parseColor(if (on) "#1B5E20" else "#B71C1C"))
            }
        }
        WatchService.refresh(this)
    }

    override fun onPause() {
        super.onPause()
        prefs.detector = address.text.toString().trim()
    }

    private fun testConnection() {
        val raw = address.text.toString().trim()
        val base = DetectorClient.normalize(raw)
        if (base == null) {
            result.setTextColor(Color.parseColor("#B71C1C"))
            result.text = "Adresa nu este bună. Folosiți de exemplu http://192.168.1.20:8000 (adresa laptopului din rețeaua locală)."
            return
        }
        prefs.detector = base
        if (raw != base) address.setText(base)
        result.setTextColor(Color.BLACK)
        result.text = "Se verifică…"
        DetectorClient.io.execute {
            val h = DetectorClient.health(base)
            runOnUiThread {
                if (h != null && h.optBoolean("ok", false)) {
                    result.setTextColor(Color.parseColor("#1B5E20"))
                    result.text = "Legătura funcționează." + if (h.optBoolean("llm", false)) " Modelul este pornit." else " Modelul nu este pornit (se folosesc doar regulile)."
                } else {
                    result.setTextColor(Color.parseColor("#B71C1C"))
                    result.text = "Nu pot ajunge la detector. Verificați că laptopul este pornit, în același Wi-Fi, și că firewall-ul permite portul 8000."
                }
            }
        }
    }

    private fun onBackground(on: Boolean) {
        if (!on) {
            prefs.background = false
            WatchService.stop(this)
            return
        }
        val base = DetectorClient.normalize(address.text.toString().trim())
        if (base == null) {
            result.setTextColor(Color.parseColor("#B71C1C"))
            result.text = "Mai întâi introduceți adresa detectorului."
            setSwitch(false)
            return
        }
        prefs.detector = base
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7)   // alerts need it; the service starts either way
        }
        prefs.background = true
        WatchService.start(this)
    }

    private fun setSwitch(v: Boolean) {
        building = true
        bgSwitch.isChecked = v
        building = false
    }
}
