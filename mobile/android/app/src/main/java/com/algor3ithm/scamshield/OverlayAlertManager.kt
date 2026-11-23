package com.algor3ithm.scamshield

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class OverlayAlertManager(private val context: Context) {

    private val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private var overlayView: View? = null

    fun showWarning(verdict: String, score: Int, warningRo: String, officialPhone: String?) {
        if (!Settings.canDrawOverlays(context)) return
        dismiss()

        val isScam = verdict == "SCAM"
        val bgColor = if (isScam) Color.parseColor("#B91C1C") else Color.parseColor("#B45309")

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgColor)
            setPadding(44, 38, 44, 38)
            elevation = 20f
        }

        val titleView = TextView(context).apply {
            text = if (isScam) "🛑 PERICOL SCAM ($score/100)" else "⚠️ MESAJ SUSPECT ($score/100)"
            setTextColor(Color.WHITE)
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
        }

        val bodyView = TextView(context).apply {
            text = warningRo.ifBlank { "Atenție! Această conversație prezintă semne de înșelăciune." }
            setTextColor(Color.WHITE)
            textSize = 15f
            setPadding(0, 14, 0, 14)
        }

        container.addView(titleView)
        container.addView(bodyView)

        if (!officialPhone.isNullOrBlank()) {
            val phoneView = TextView(context).apply {
                text = "📞 Canal oficial: $officialPhone"
                setTextColor(Color.parseColor("#FEF08A"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                setPadding(0, 0, 0, 14)
            }
            container.addView(phoneView)
        }

        val closeBtn = Button(context).apply {
            text = "AM ÎNȚELES — ÎNCHIDE ALERTA"
            setBackgroundColor(Color.WHITE)
            setTextColor(bgColor)
            setOnClickListener { dismiss() }
        }
        container.addView(closeBtn)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = 90
        }

        overlayView = container
        windowManager.addView(container, params)
    }

    fun dismiss() {
        overlayView?.let {
            runCatching { windowManager.removeView(it) }
            overlayView = null
        }
    }
}