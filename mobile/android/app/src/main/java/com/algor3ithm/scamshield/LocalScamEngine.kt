package com.algor3ithm.scamshield

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class AnalysisResult(
    val verdict: String,
    val scamType: String,
    val riskScore: Int,
    val redFlags: List<String>,
    val warningRo: String,
    val officialOrg: String?,
    val officialPhone: String?
)

class LocalScamEngine(context: Context) {

    private val redFlagPoints = mutableMapOf<String, Int>()
    private val officialDomains = mutableSetOf<String>()
    private val officialBrands = mutableSetOf<String>()
    private val officialContacts = mutableListOf<JSONObject>()

    init {
        val rawJson = context.assets.open("official_catalog.json").bufferedReader().use { it.readText() }
        val catalog = JSONObject(rawJson)

        val pointsObj = catalog.getJSONObject("red_flag_points")
        pointsObj.keys().forEach { key ->
            redFlagPoints[key] = pointsObj.getInt(key)
        }

        val contactsArr: JSONArray = catalog.getJSONArray("official_contacts")
        for (i in 0 until contactsArr.length()) {
            val item = contactsArr.getJSONObject(i)
            officialContacts.add(item)
            val website = item.optString("website", "").lowercase().trim()
            if (website.isNotEmpty()) officialDomains.add(website)
            val org = item.optString("organisation", "").lowercase().trim()
            if (org.isNotEmpty()) officialBrands.add(org)
        }
    }

    private fun extractDomains(text: String): List<String> {
        val regex = Regex("(?:https?://)?(?:www\\.)?([a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+)")
        return regex.findAll(text.lowercase())
            .map { it.groupValues[1] }
            .filter { !it.matches(Regex("^\\d+\\.\\d+$")) }
            .toList()
    }

    private fun isOfficialDomain(domain: String): Boolean {
        return officialDomains.any { off -> domain == off || domain.endsWith(".$off") }
    }

    fun analyzeThread(
        contactTitle: String,
        isPhoneNumber: Boolean,
        messages: List<Pair<String, String>> // Pair(from, text)
    ): AnalysisResult {
        val cumulativeFlags = LinkedHashSet<String>()
        val knownContact = !isPhoneNumber
        val senderLower = contactTitle.lowercase()

        for ((idx, msg) in messages.withIndex()) {
            val (from, text) = msg
            if (from == "reader") continue

            val textLower = text.lowercase()
            val isOtpWarning = listOf("nu comunicați acest cod", "nu comunicati acest cod", "nu îl dați", "nu il dati")
                .any { it in textLower }

            val domains = extractDomains(text)
            val hasOfficialLink = domains.any { isOfficialDomain(it) }
            val hasUnofficialLink = domains.any { !isOfficialDomain(it) }

            val hasUnofficialEmail = if ("@" in senderLower) {
                val dom = senderLower.substringAfterLast("@")
                !isOfficialDomain(dom)
            } else false

            if (isOtpWarning && !hasUnofficialLink && !hasUnofficialEmail) {
                cumulativeFlags.clear()
                continue
            }

            if (hasOfficialLink && !hasUnofficialLink && ("ramburs: 0" in textLower || "comanda efectuată" in textLower)) {
                cumulativeFlags.clear()
                continue
            }

            if (hasUnofficialLink || hasUnofficialEmail) cumulativeFlags.add("RF_SUSPICIOUS_CONTACT")

            if (listOf("anydesk", "teamviewer", "rustdesk", "de la distanță", "de la distanta").any { it in textLower }) {
                cumulativeFlags.add("RF_REMOTE_ACCESS")
            }

            if (!isOtpWarning && listOf(
                    "trimite-mi codul", "trimite codul", "codul primit", "mi-l poți trimite",
                    "mi-l poti trimite", "mi-l citiți", "mi-l cititi", "cod de confirmare, pe care"
                ).any { it in textLower }
            ) {
                cumulativeFlags.add("RF_CODE_REQUEST")
            }

            if (listOf(
                    "datele cardului", "numărul cardului", "numarul cardului", "cnp", "parola",
                    "pin", "poza buletin", "poza cu buletinul", "intrați în contul de bancă",
                    "intrati in contul de banca", "confirmăm datele", "confirmam datele", "completați datele", "completati datele"
                ).any { it in textLower }
            ) {
                cumulativeFlags.add("RF_DATA_REQUEST")
            }

            if ("ramburs: 0" !in textLower && listOf(
                    "achitați taxa", "achitati taxa", "transfer de", "faci tu un transfer",
                    "plătiți", "platiti", "depuneți", "depuneti", "taxa de reprogramare", "plătesc azi o factură",
                    "pentru un uber", "bani de uber", "bani pentru un uber", "pentru un bolt", "bani de bolt", "bani de taxi",
                    "îmi dai și mie", "imi dai si mie", "să îmi dai", "sa imi dai", "împrumuți", "imprumuti",
                    "trimite-mi pe revolut", "pe revolut", "nu am cu ce să ajung", "nu am cu ce sa ajung"
                ).any { it in textLower }
            ) {
                cumulativeFlags.add("RF_PAYMENT_REQUEST")
            }

            val isBrandSender = officialBrands.any { it.replace(" ", "") in senderLower.replace(" ", "") }
            if (idx == 0 && !knownContact && !isBrandSender) {
                if (listOf("numărul nou", "numarul nou", "mi s-a stricat telefonul", "număr nou", "numar nou").any { it in textLower }) {
                    cumulativeFlags.add("RF_NEW_NUMBER")
                }
            }

            if (listOf("nu-i spune", "nu îi spune", "nu ii spune", "păstrează secret", "pastreaza secret", "între noi", "intre noi").any { it in textLower }) {
                cumulativeFlags.add("RF_SECRECY")
            }

            if (listOf(
                    "câștigătorul", "castigatorul", "ați câștigat", "ati castigat", "tombola",
                    "rambursare de", "restituire de", "va crește cu", "va creste cu", "garantat", "premiu"
                ).any { it in textLower }
            ) {
                cumulativeFlags.add("RF_TOO_GOOD")
            }

            if (listOf(
                    "banca dunărea", "banca dunarea", "curierexpres", "anaf", "megashop",
                    "suportul tehnic", "casa de pensii", "poliția", "politia", "stimate contribuabil"
                ).any { it in textLower }
            ) {
                cumulativeFlags.add("RF_IMPERSONATION")
            }

            if (listOf("în 24h", "in 24h", "urgent", "expiră", "expira", "grăbiți", "grabiti", "până la", "pana la", "plătesc azi", "platesc azi").any { it in textLower }) {
                cumulativeFlags.add("RF_URGENCY")
            }

            if (listOf("blocat", "suspendat", "viruși", "virusi", "virus", "amendă", "amenda", "poprire", "v-au furat bani").any { it in textLower }) {
                cumulativeFlags.add("RF_THREAT")
            }

            if (listOf("accident", "spital", "te implor", "ajută-mă", "ajuta-ma").any { it in textLower }) {
                cumulativeFlags.add("RF_EMOTIONAL_PRESSURE")
            }

            if (listOf("pe telegram", "pe whatsapp", "altă aplicație", "alta aplicatie").any { it in textLower }) {
                cumulativeFlags.add("RF_CHANNEL_SWITCH")
            }
        }

        val finalScore = minOf(100, cumulativeFlags.sumOf { redFlagPoints[it] ?: 0 })
        val verdict = when {
            finalScore >= 50 -> "SCAM"
            finalScore >= 25 -> "SUSPICIOUS"
            else -> "SAFE"
        }

        if (verdict == "SAFE") {
            return AnalysisResult("SAFE", "NONE", 0, emptyList(), "", null, null)
        }

        val fullSenderText = messages.filter { it.first == "sender" }.joinToString(" ") { it.second }.lowercase()
        val scamType = inferScamType(cumulativeFlags, "$fullSenderText $senderLower")
        val (warningRo, org, phone) = buildWarningAndOfficial(scamType, cumulativeFlags)

        return AnalysisResult(verdict, scamType, finalScore, cumulativeFlags.toList(), warningRo, org, phone)
    }

    private fun inferScamType(flags: Set<String>, t: String): String {
        return when {
            "RF_REMOTE_ACCESS" in flags || Regex("\\b(suportul tehnic|suport tehnic|teamviewer|anydesk|rustdesk|virus|viruși|virusi)\\b").containsMatchIn(t) -> "TECH_SUPPORT"
            Regex("\\b(piatamea|piațamea|olx|vinted|livrare sigură|livrare sigura|cumpărător|cumparator|anunț|anunt)\\b").containsMatchIn(t) -> "MARKETPLACE"
            Regex("\\b(curier|curierexpres|colet|coletul|awb|taxa de reprogramare|livrare)\\b").containsMatchIn(t) -> "COURIER_FEE"
            "RF_NEW_NUMBER" in flags || Regex("\\b(mami|mama|tati|tata|bunico|bunicule|numărul nou|numarul nou)\\b").containsMatchIn(t) -> "FAMILY_EMERGENCY"
            Regex("\\b(anaf|pensii|contribuabil|poliția|politia|impozit|guvern)\\b").containsMatchIn(t) -> "AUTHORITY_IMPERSONATION"
            Regex("\\b(tombola|tombolă|câștigătorul|castigatorul|ați câștigat|ati castigat|premiu|loterie)\\b").containsMatchIn(t) -> "PRIZE_LOTTERY"
            "RF_CODE_REQUEST" in flags -> "ACCOUNT_TAKEOVER"
            "RF_PAYMENT_REQUEST" in flags && Regex("\\b(uber|bolt|taxi|revolut|împrumut|imprumut|ajung)\\b").containsMatchIn(t) -> "ACCOUNT_TAKEOVER"
            Regex("\\b(banca|bancă|cardul|contul de bancă|tranzacți|iban)\\b").containsMatchIn(t) -> "BANK_IMPERSONATION"
            else -> "OTHER"
        }
    }

    private fun buildWarningAndOfficial(scamType: String, flags: Set<String>): Triple<String, String?, String?> {
        val matchedContact = officialContacts.firstOrNull { c ->
            c.optString("category", "").equals(scamType, ignoreCase = true)
        }
        val org = matchedContact?.optString("organisation")?.takeIf { it.isNotBlank() }
        val phone = matchedContact?.optString("phone")?.takeIf { it.isNotBlank() }

        val warning = when (scamType) {
            "FAMILY_EMERGENCY" ->
                "OPREȘTE-TE! Cineva se dă drept o rudă de pe un număr nou și cere bani. NU trimite bani! Sună-ți ruda pe numărul ei vechi din agendă."
            "ACCOUNT_TAKEOVER" ->
                "ATENȚIE! Cineva îți cere bani sau un cod secret. Contul persoanei ar putea fi spart. Sun-o la telefon înainte să trimiți ceva!"
            "BANK_IMPERSONATION" ->
                "PERICOL! Banca NU îți cere niciodată datele cardului, PIN-ul sau coduri prin mesaje. Nu răspunde și nu apăsa pe niciun link."
            "COURIER_FEE" ->
                "CAPCANĂ! Curierul nu cere plata prin link-uri trimise pe mesaj. Nu apăsa pe link și nu trece datele cardului."
            "TECH_SUPPORT" ->
                "PERICOL! Nu instala nicio aplicație cerută în acest mesaj — altcineva îți poate controla telefonul și îți poate lua banii din cont."
            "AUTHORITY_IMPERSONATION" ->
                "ATENȚIE! Instituțiile statului nu cer bani sau date personale prin mesaje pe WhatsApp. Nu trimite nimic!"
            "PRIZE_LOTTERY" ->
                "CAPCANĂ! Nu ai câștigat niciun premiu. Nu da datele cardului și nu plăti nicio taxă ca să primești bani."
            else ->
                "ATENȚIE! Acest mesaj pare o păcăleală. NU trimite bani, coduri sau poze cu buletinul. Cere sfatul unei persoane de încredere!"
        }
        return Triple(warning, org, phone)
    }
}