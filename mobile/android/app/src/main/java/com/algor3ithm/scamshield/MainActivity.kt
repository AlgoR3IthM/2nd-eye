package com.algor3ithm.scamshield

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.view.Gravity
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var modelStatusText: TextView

    private val pickModelLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            copyModelToPrivateStorage(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
            gravity = Gravity.CENTER_HORIZONTAL
        }

        val title = TextView(this).apply {
            text = "ScamShield — Protecție WhatsApp"
            textSize = 24f
            setPadding(0, 0, 0, 24)
        }

        statusText = TextView(this).apply {
            textSize = 18f
            setPadding(0, 16, 0, 32)
        }

        val btnAccessibility = Button(this).apply {
            text = "1. Activează Protecția (Accesibilitate)"
            textSize = 16f
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
        }

        val btnOverlay = Button(this).apply {
            text = "2. Permite Alertele pe Ecran"
            textSize = 16f
            setOnClickListener {
                val intent = Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName")
                )
                startActivity(intent)
            }
        }

        modelStatusText = TextView(this).apply {
            textSize = 15f
            setPadding(0, 40, 0, 16)
        }

        val btnImportModel = Button(this).apply {
            text = "3. Încarcă Model AI (.gguf) din Telefon (Opțional)"
            textSize = 15f
            setOnClickListener {
                pickModelLauncher.launch(arrayOf("*/*"))
            }
        }

        layout.addView(title)
        layout.addView(statusText)
        layout.addView(btnAccessibility)
        layout.addView(btnOverlay)
        layout.addView(modelStatusText)
        layout.addView(btnImportModel)

        setContentView(layout)
    }

    override fun onResume() {
        super.onResume()
        refreshStatuses()
    }

    private fun refreshStatuses() {
        val accEnabled = isAccessibilityEnabled()
        val overlayEnabled = Settings.canDrawOverlays(this)

        statusText.text = buildString {
            appendLine(if (accEnabled) "✅ Protecție WhatsApp: ACTIVĂ" else "❌ Protecție WhatsApp: OPRITĂ")
            append(if (overlayEnabled) "✅ Alerte Vizuale: PERMISE" else "❌ Alerte Vizuale: BLOCATE")
        }

        val modelFile = File(filesDir, "scamshield-3b.gguf")
        modelStatusText.text = if (modelFile.exists()) {
            "🧠 Model AI Local: ACTIV (${modelFile.length() / (1024 * 1024)} MB)"
        } else {
            "⚡ Mod Rapid Activ (Reguli + Catalog Oficial). Pentru AI suplimentar, încarcă fișierul .gguf:"
        }
    }

    private fun copyModelToPrivateStorage(uri: Uri) {
        modelStatusText.text = "⏳ Se copiază modelul AI în aplicație (~15 secunde)..."
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val destFile = File(filesDir, "scamshield-3b.gguf")
                contentResolver.openInputStream(uri)?.use { input ->
                    destFile.outputStream().use { output ->
                        input.copyTo(output, bufferSize = 1024 * 1024)
                    }
                }
                withContext(Dispatchers.Main) {
                    refreshStatuses()
                    Toast.makeText(this@MainActivity, "Modelul AI a fost încărcat cu succes!", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    modelStatusText.text = "❌ Eroare la copiere: ${e.message}"
                }
            }
        }
    }

    private fun isAccessibilityEnabled(): Boolean {
        val expected = ComponentName(this, WhatsAppMonitorService::class.java).flattenToString()
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(enabledServices)
        while (splitter.hasNext()) {
            if (splitter.next().equals(expected, ignoreCase = true)) return true
        }
        return false
    }
}