package com.algor3ithm.scamshield

import android.accessibilityservice.AccessibilityService
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File

class WhatsAppMonitorService : AccessibilityService() {

    private val handler = Handler(Looper.getMainLooper())
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pendingRunnable: Runnable? = null
    private var lastAnalyzedHash: Int = 0

    private val alertedRisksPerContact = mutableMapOf<String, Pair<String, Long>>()
    private val alertCooldownMs = 120_000L

    private lateinit var overlayManager: OverlayAlertManager
    private lateinit var localEngine: LocalScamEngine
    @Volatile private var isLlmReady = false

    override fun onServiceConnected() {
        super.onServiceConnected()
        overlayManager = OverlayAlertManager(this)
        localEngine = LocalScamEngine(this)

        // Încărcăm modelul scamshield-3b.gguf pe background la pornirea serviciului
        serviceScope.launch {
            val modelFile = File(filesDir, "scamshield-3b.gguf")
            if (modelFile.exists()) {
                try {
                    isLlmReady = OnDeviceLlm.initModel(modelFile.absolutePath)
                    Log.d("ScamShield", "OnDeviceLlm inițializat: $isLlmReady (${modelFile.length() / (1024 * 1024)} MB)")
                } catch (t: Throwable) {
                    Log.e("ScamShield", "Eroare la încărcarea OnDeviceLlm: ${t.message}")
                }
            } else {
                Log.w("ScamShield", "Modelul GGUF nu există la ${modelFile.absolutePath}")
            }
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val pkg = event?.packageName?.toString() ?: return
        if (pkg != "com.whatsapp" && pkg != "com.whatsapp.w4b") return

        pendingRunnable?.let { handler.removeCallbacks(it) }
        pendingRunnable = Runnable {
            val freshRoot = rootInActiveWindow ?: return@Runnable
            extractAndAnalyzeThread(freshRoot)
        }
        handler.postDelayed(pendingRunnable!!, 500)
    }

    private fun extractAndAnalyzeThread(root: AccessibilityNodeInfo) {
        val screenWidth = resources.displayMetrics.widthPixels
        val screenHeight = resources.displayMetrics.heightPixels

        val titleNodes = root.findAccessibilityNodeInfosByViewId("com.whatsapp:id/conversation_contact_name")
        val entryNodes = root.findAccessibilityNodeInfosByViewId("com.whatsapp:id/entry")
        if (titleNodes.isEmpty() && entryNodes.isEmpty()) return

        val contactTitle = titleNodes.firstOrNull()?.text?.toString()?.trim() ?: "Unknown"
        val isPhoneNumber = contactTitle.startsWith("+") || contactTitle.replace(" ", "").all { it.isDigit() }

        val candidateNodes = mutableListOf<AccessibilityNodeInfo>()
        val byId = root.findAccessibilityNodeInfosByViewId("com.whatsapp:id/message_text")
        if (byId.isNotEmpty()) {
            candidateNodes.addAll(byId)
        } else {
            collectTextNodes(root, candidateNodes, screenHeight)
        }

        if (candidateNodes.isEmpty()) return

        val parsedMessages = mutableListOf<Pair<String, String>>()
        val senderTexts = mutableListOf<String>()

        for (node in candidateNodes) {
            val text = node.text?.toString()?.trim() ?: continue
            if (text.length < 3 || text.matches(Regex("^\\d{1,2}:\\d{2}$"))) continue
            if (text.equals("Message", ignoreCase = true) || text.equals("Mesaj", ignoreCase = true)) continue

            val rect = Rect()
            node.getBoundsInScreen(rect)
            val from = if (rect.left > screenWidth * 0.35) "reader" else "sender"

            parsedMessages.add(Pair(from, text))
            if (from == "sender") {
                senderTexts.add(text)
            }
        }

        if (senderTexts.isEmpty()) return

        val recentSenderSignature = senderTexts.takeLast(3).joinToString("|")
        val currentHash = "$contactTitle::$recentSenderSignature".hashCode()
        if (currentHash == lastAnalyzedHash) return
        lastAnalyzedHash = currentHash

        // 1. Evaluare deterministă + domenii oficiale (< 5 ms)
        val localResult = localEngine.analyzeThread(contactTitle, isPhoneNumber, parsedMessages)
        Log.d("ScamShield", "LocalEngine -> verdict=${localResult.verdict}, score=${localResult.riskScore}")

        if (localResult.verdict == "SCAM" || localResult.verdict == "SUSPICIOUS") {
            triggerAlertIfNotDuplicate(
                contactTitle = contactTitle,
                verdict = localResult.verdict,
                score = localResult.riskScore,
                scamType = localResult.scamType,
                redFlagsSignature = localResult.redFlags.toString(),
                warningRo = localResult.warningRo,
                officialPhone = localResult.officialPhone
            )
        }

        // 2. Rafinare cu modelul fine-tuned scamshield-3b.gguf direct pe telefon
        if (isLlmReady) {
            val recentDialog = parsedMessages.takeLast(4).joinToString("\n") { "${it.first}: ${it.second}" }
            serviceScope.launch {
                try {
                    val prompt = buildPrompt(contactTitle, recentDialog)
                    val rawOut = OnDeviceLlm.generateJson(prompt)
                    Log.d("ScamShield", "OnDeviceLlm output: ${rawOut.length} chars")  // never log model text: it can quote the messages
                    val jsonStart = rawOut.indexOf('{')
                    val jsonEnd = rawOut.lastIndexOf('}')
                    if (jsonStart >= 0 && jsonEnd > jsonStart) {
                        val llmJson = JSONObject(rawOut.substring(jsonStart, jsonEnd + 1))
                        val llmVerdict = llmJson.optString("verdict", "SAFE")
                        val llmWarning = llmJson.optString("warning_ro", "")
                        val llmType = llmJson.optString("scam_type", "OTHER")

                        if ((llmVerdict == "SCAM" || llmVerdict == "SUSPICIOUS") && localResult.verdict == "SAFE" && llmWarning.isNotBlank()) {
                            triggerAlertIfNotDuplicate(
                                contactTitle = contactTitle,
                                verdict = llmVerdict,
                                score = if (llmVerdict == "SCAM") 60 else 35,
                                scamType = llmType,
                                redFlagsSignature = "LLM_$llmType",
                                warningRo = llmWarning,
                                officialPhone = null
                            )
                        }
                    }
                } catch (e: Exception) {
                    Log.e("ScamShield", "Eroare inferență LLM: ${e.message}")
                }
            }
        }
    }

    private fun buildPrompt(sender: String, conversation: String): String {
        return """<|im_start|>system
Ești ScamShield, un asistent care protejează persoanele în vârstă de înșelăciuni pe WhatsApp. Răspunzi strict în format JSON valid cu cheile: "verdict" ("SAFE", "SUSPICIOUS" sau "SCAM"), "scam_type", "warning_ro". Scrie "warning_ro" în limba română, foarte simplu, clar și calm (maxim 2 propoziții scurte, fără termeni tehnici), spunând exact ce să NU facă (ex: NU trimite bani, NU da datele cardului) și ce să facă (ex: sună ruda pe numărul vechi).<|im_end|>
<|im_start|>user
Expeditor: $sender
Conversație:
$conversation<|im_end|>
<|im_start|>assistant
"""
    }

    private fun triggerAlertIfNotDuplicate(
        contactTitle: String,
        verdict: String,
        score: Int,
        scamType: String,
        redFlagsSignature: String,
        warningRo: String,
        officialPhone: String?
    ) {
        val riskSignature = "$verdict|$scamType|$redFlagsSignature"
        val now = System.currentTimeMillis()
        val previous = alertedRisksPerContact[contactTitle]

        if (previous != null && previous.first == riskSignature && (now - previous.second) < alertCooldownMs) {
            return
        }
        alertedRisksPerContact[contactTitle] = Pair(riskSignature, now)

        handler.post {
            overlayManager.showWarning(verdict, score, warningRo, officialPhone)
        }
    }

    private fun collectTextNodes(node: AccessibilityNodeInfo?, out: MutableList<AccessibilityNodeInfo>, screenHeight: Int) {
        if (node == null) return
        if (node.className == "android.widget.TextView" && !node.text.isNullOrBlank()) {
            val rect = Rect()
            node.getBoundsInScreen(rect)
            if (rect.top > screenHeight * 0.13 && rect.bottom < screenHeight * 0.88) {
                out.add(node)
            }
        }
        for (i in 0 until node.childCount) {
            collectTextNodes(node.getChild(i), out, screenHeight)
        }
    }

    override fun onInterrupt() {
        overlayManager.dismiss()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}