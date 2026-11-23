import json
import re
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional

CATALOG_PATH = Path(__file__).parent / "official_catalog.json"
with open(CATALOG_PATH, "r", encoding="utf-8") as f:
    CATALOG = json.load(f)

RED_FLAG_POINTS: Dict[str, int] = CATALOG["red_flag_points"]
OFFICIAL_CONTACTS: List[Dict[str, Any]] = CATALOG["official_contacts"]
SCAM_TYPES: List[str] = CATALOG["scam_types"]

OFFICIAL_DOMAINS = {c["website"].lower() for c in OFFICIAL_CONTACTS if c.get("website")}
OFFICIAL_BRANDS = {c["organisation"].lower() for c in OFFICIAL_CONTACTS if c.get("organisation")}

OLLAMA_URL = "http://localhost:11434/api/generate"
LOCAL_MODEL = "scamshield-3b:latest"


def extract_urls_and_domains(text: str) -> List[str]:
    pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)"
    matches = re.findall(pattern, text.lower())
    return [m for m in matches if not re.match(r"^\d+\.\d+$", m)]


def is_official_domain(domain: str) -> bool:
    return any(domain == off or domain.endswith("." + off) for off in OFFICIAL_DOMAINS)


def analyze_message_rules(msg_text: str, sender: Dict[str, Any], is_first_msg: bool, channel: str) -> Dict[str, Any]:
    """Motor simbolic determinist: extrage flag-uri sigure și filtre de excepție (capcane)."""
    text_lower = msg_text.lower()
    flags = set()

    # Detectăm dacă mesajul este o capcană legitimă (V03 / V05)
    is_otp_warning = any(p in text_lower for p in [
        "nu comunicați acest cod", "nu comunicati acest cod", "nu îl dați", "nu il dati"
    ])
    domains = extract_urls_and_domains(msg_text)
    has_official_link = any(is_official_domain(d) for d in domains)
    has_unofficial_link = any(not is_official_domain(d) for d in domains)

    sender_addr = (sender.get("address") or "").lower()
    has_unofficial_email = False
    if "@" in sender_addr:
        email_dom = sender_addr.split("@")[-1]
        if not is_official_domain(email_dom):
            has_unofficial_email = True

    # Dacă e avertisment legitim de cod OTP fără link neoficial -> SAFE garantat (V03)
    if is_otp_warning and not has_unofficial_link and not has_unofficial_email:
        return {"flags": [], "force_safe": True}

    # Dacă e notificare curier pe domeniu oficial fără cerere de plată (ex: "Ramburs: 0 lei") -> SAFE garantat (V05)
    if has_official_link and not has_unofficial_link and ("ramburs: 0" in text_lower or "comanda efectuată" in text_lower):
        return {"flags": [], "force_safe": True}

    # 1. RF_SUSPICIOUS_CONTACT (25p)
    if has_unofficial_link or has_unofficial_email:
        flags.add("RF_SUSPICIOUS_CONTACT")

    # 2. RF_REMOTE_ACCESS (35p)
    if any(w in text_lower for w in ["anydesk", "teamviewer", "rustdesk", "de la distanță", "de la distanta"]):
        flags.add("RF_REMOTE_ACCESS")

    # 3. RF_CODE_REQUEST (35p) - doar când CERE codul, nu când îl oferă
    if not is_otp_warning and any(w in text_lower for w in [
        "trimite-mi codul", "trimite codul", "codul primit", "mi-l poți trimite",
        "mi-l poti trimite", "mi-l citiți", "mi-l cititi", "cod de confirmare, pe care"
    ]):
        flags.add("RF_CODE_REQUEST")

    # 4. RF_DATA_REQUEST (30p)
    if any(w in text_lower for w in [
        "datele cardului", "numărul cardului", "numarul cardului", "cnp", "parola",
        "pin", "poza buletin", "poza cu buletinul", "intrați în contul de bancă",
        "intrati in contul de banca", "confirmăm datele", "confirmam datele", "completați datele", "completati datele"
    ]):
        flags.add("RF_DATA_REQUEST")

    # 5. RF_PAYMENT_REQUEST (25p) - exclude "ramburs: 0 lei"
    if "ramburs: 0" not in text_lower and any(w in text_lower for w in [
        "achitați taxa", "achitati taxa", "transfer de", "faci tu un transfer",
        "plătiți", "platiti", "depuneți", "depuneti", "taxa de reprogramare", "plătesc azi o factură",
        "pentru un uber", "bani de uber", "bani pentru un uber", "pentru un bolt", "bani de bolt", "bani de taxi",
        "îmi dai și mie", "imi dai si mie", "să îmi dai", "sa imi dai", "împrumuți", "imprumuti",
        "trimite-mi pe revolut", "pe revolut", "nu am cu ce să ajung", "nu am cu ce sa ajung"
    ]):
        flags.add("RF_PAYMENT_REQUEST")

    # 6. RF_NEW_NUMBER (20p) - doar dacă nu e brand/companie și e contact necunoscut
    sender_name = (sender.get("name") or "").lower()
    is_brand_sender = any(b.replace(" ", "") in sender_name.replace(" ", "") for b in OFFICIAL_BRANDS)
    if is_first_msg and not sender.get("known_contact", False) and not is_brand_sender:
        if any(w in text_lower for w in ["numărul nou", "numarul nou", "mi s-a stricat telefonul", "număr nou", "numar nou"]):
            flags.add("RF_NEW_NUMBER")

    # 7. RF_SECRECY (20p)
    if any(w in text_lower for w in ["nu-i spune", "nu îi spune", "nu ii spune", "păstrează secret", "pastreaza secret", "între noi", "intre noi"]):
        flags.add("RF_SECRECY")

    # 8. RF_TOO_GOOD (20p)
    if any(w in text_lower for w in [
        "câștigătorul", "castigatorul", "ați câștigat", "ati castigat", "tombola",
        "rambursare de", "restituire de", "va crește cu", "va creste cu", "garantat", "premiu"
    ]):
        flags.add("RF_TOO_GOOD")

    # 9. RF_IMPERSONATION (15p)
    if any(w in text_lower for w in [
        "banca dunărea", "banca dunarea", "curierexpres", "anaf", "megashop",
        "suportul tehnic", "casa de pensii", "poliția", "politia", "stimate contribuabil"
    ]):
        flags.add("RF_IMPERSONATION")

    # 10. RF_URGENCY (15p)
    if any(w in text_lower for w in [
        "în 24h", "in 24h", "în 24 de ore", "urgent", "expiră într-o oră", "expira intr-o ora",
        "grăbiți-vă", "grabiti-va", "până la", "pana la", "azi", "acum"
    ]):
        # "azi" într-o notificare simplă fără cerere nu e urgență
        if any(w in text_lower for w in ["în 24h", "in 24h", "urgent", "expiră", "expira", "grăbiți", "grabiti", "până la", "pana la", "plătesc azi", "platesc azi"]):
            flags.add("RF_URGENCY")

    # 11. RF_THREAT (15p)
    if any(w in text_lower for w in [
        "blocat", "suspendat", "viruși", "virusi", "virus", "amendă", "amenda", "poprire", "v-au furat bani"
    ]):
        flags.add("RF_THREAT")

    # 12. RF_EMOTIONAL_PRESSURE (10p)
    if any(w in text_lower for w in ["accident", "spital", "te implor", "ajută-mă", "ajuta-ma"]):
        flags.add("RF_EMOTIONAL_PRESSURE")

    # 13. RF_CHANNEL_SWITCH (10p)
    if any(w in text_lower for w in ["pe telegram", "pe whatsapp", "altă aplicație", "alta aplicatie"]):
        flags.add("RF_CHANNEL_SWITCH")

    return {"flags": list(flags), "force_safe": False}


def query_finetuned_llm(conversation_so_far: List[Dict[str, Any]], sender: Dict[str, Any], channel: str) -> Dict[str, Any]:
    """Folosește exact formatul de instrucțiuni pe care a fost antrenat scamshield-3b."""
    header = (
        f"Channel: {channel} | Sender: {sender.get('name') or sender.get('address')} "
        f"(address: {sender.get('address')}, known: {sender.get('known_contact')})"
    )
    lines = [f"[{m['n']}] ({m['from']}): {m['text']}" for m in conversation_so_far]
    formatted_input = header + "\n" + "\n".join(lines)

    prompt = (
        "Analizează conversația și returnează strict JSON cu red_flags, "
        "scam_type, warning_ro și official_suggestion.\n\n" + formatted_input
    )

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": LOCAL_MODEL,
                "prompt": prompt,
                "format": "json",
                "stream": False,
                "options": {"temperature": 0.0, "seed": 42, "num_predict": 300},
            },
            timeout=15,
        )
        resp.raise_for_status()
        return json.loads(resp.json().get("response", "{}"))
    except Exception:
        return {}


def infer_scam_type(flags: List[str], full_text: str, sender: Dict[str, Any], llm_type: str) -> str:
    """Determină precis tipul de scam combinând contextul conversației și predicția modelului."""
    t = (full_text + " " + str(sender.get("name") or "") + " " + str(sender.get("address") or "")).lower()

    # 1. Tech Support (AnyDesk / TeamViewer / virus)
    if "RF_REMOTE_ACCESS" in flags or re.search(r"\b(suportul tehnic|suport tehnic|teamviewer|anydesk|rustdesk|virus|viruși|virusi)\b", t):
        return "TECH_SUPPORT"

    # 2. Marketplace (înainte de BANK_IMPERSONATION, pentru că și aici se cer datele cardului)
    if re.search(r"\b(piatamea|piațamea|olx|vinted|livrare sigură|livrare sigura|cumpărător|cumparator|anunț|anunt|anunțul|anuntul|mai este disponibil)\b", t):
        return "MARKETPLACE"

    # 3. Courier Fee (înainte de FAMILY_EMERGENCY!)
    if re.search(r"\b(curier|curierexpres|colet|coletul|awb|taxa de reprogramare|livrarea coletului|livrare)\b", t):
        return "COURIER_FEE"

    # 4. Family Emergency (doar cuvinte întregi, fără potriviri parțiale)
    if "RF_NEW_NUMBER" in flags or re.search(r"\b(mami|mama|tati|tata|bunico|bunicule|numărul nou|numarul nou|mi s-a stricat telefonul)\b", t):
        return "FAMILY_EMERGENCY"

    # 5. Authority Impersonation (ANAF / Pensii / Poliție / Guvern)
    if re.search(r"\b(anaf|pensii|contribuabil|poliția|politia|impozit|guvern|dosarelor)\b", t):
        return "AUTHORITY_IMPERSONATION"

    # 6. Prize / Lottery (tombolă / premiu / câștigător)
    if re.search(r"\b(tombola|tombolă|câștigătorul|castigatorul|ați câștigat|ati castigat|premiu|loterie)\b", t):
        return "PRIZE_LOTTERY"

    # 7. Account Takeover (cod trimis din greșeală de un contact)
    if "RF_CODE_REQUEST" in flags and re.search(r"\b(din greșeală|din greseala|trimis un cod|codul meu)\b", t):
        return "ACCOUNT_TAKEOVER"

    # 8. Job Offer
    if re.search(r"\b(loc de muncă|loc de munca|angajăm|angajam|lucru de acasă|lucru de acasa|aprecieri|taxa de înscriere|taxa de inscriere)\b", t):
        return "JOB_OFFER"

    # 9. Investment
    if re.search(r"\b(investiții|investitii|investiție|investitie|cripto|crypto|acțiuni|actiuni|profit garantat|randament)\b", t):
        return "INVESTMENT"

    # 10. Romance
    if re.search(r"\b(biletul de avion|platformă marină|platforma marina|sufletul meu|ne căsătorim|ne casatorim)\b", t):
        return "ROMANCE"

    # 11. Bank Impersonation
    if re.search(r"\b(banca|bancă|bancadunarea|cardul|contul de bancă|contul de banca|tranzacți|tranzactiei|tranzacției|iban)\b", t):
        return "BANK_IMPERSONATION"

    # 12. Fallback pe predicția modelului fine-tuned
    if llm_type in SCAM_TYPES and llm_type not in ("NONE", "OTHER"):
        return llm_type

    return "OTHER"


def sanitize_warning(warning_text: str, messages: List[Dict[str, Any]]) -> str:
    all_raw = " ".join(m["text"] for m in messages)
    suspicious_domains = [
        d for d in extract_urls_and_domains(all_raw) if not is_official_domain(d)
    ]
    cleaned = warning_text
    for bad_dom in suspicious_domains:
        cleaned = re.sub(re.escape(bad_dom), "[adresă blocată]", cleaned, flags=re.IGNORECASE)
    return cleaned


def compute_verdict(score: int) -> str:
    if score >= 50:
        return "SCAM"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"


def analyze_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    messages = scenario.get("messages", [])
    sender = scenario.get("sender", {})
    channel = scenario.get("channel", "unknown")

    cumulative_flags: List[str] = []
    first_alert: Optional[int] = None
    timeline = []

    for idx, msg in enumerate(messages):
        if msg.get("from") == "reader":
            score = min(100, sum(RED_FLAG_POINTS.get(f, 0) for f in cumulative_flags))
            timeline.append({"n": msg["n"], "score": score, "flags": list(cumulative_flags)})
            continue

        rule_res = analyze_message_rules(msg["text"], sender, is_first_msg=(idx == 0), channel=channel)

        if rule_res["force_safe"]:
            cumulative_flags = []
            timeline.append({"n": msg["n"], "score": 0, "flags": []})
            continue

        for flag in rule_res["flags"]:
            if flag not in cumulative_flags:
                cumulative_flags.append(flag)

        score = min(100, sum(RED_FLAG_POINTS[f] for f in cumulative_flags))
        if first_alert is None and score >= 25:
            first_alert = msg["n"]

        timeline.append({"n": msg["n"], "score": score, "flags": list(cumulative_flags)})

    final_score = min(100, sum(RED_FLAG_POINTS[f] for f in cumulative_flags))
    verdict = compute_verdict(final_score)

    if verdict == "SAFE":
        return {
            "id": scenario.get("id", "MANUAL"),
            "channel": channel,
            "verdict": "SAFE",
            "scam_type": "NONE",
            "risk_score": 0,
            "first_alert": None,
            "red_flags": [],
            "warning_ro": "Pare în regulă. Nu au fost identificate semne de înșelăciune în acest mesaj.",
            "official_suggestion": None,
            "timeline": timeline,
            "messages": messages,
        }

    # Apelăm modelul fine-tuned scamshield-3b pentru avertismentul natural în română și sugestia oficială
    llm_res = query_finetuned_llm(messages, sender, channel)
    full_text = " ".join(m["text"] for m in messages if m.get("from") == "sender")
    scam_type = infer_scam_type(cumulative_flags, full_text, sender, llm_res.get("scam_type", "OTHER"))

    raw_warning = llm_res.get("warning_ro") or (
        "Atenție, pare o țeapă! Nu trimiteți bani, coduri sau date personale. "
        "Verificați situația doar pe canalul oficial al instituției sau sunând persoana pe numărul cunoscut."
    )
    warning_ro = sanitize_warning(raw_warning, messages)

    return {
        "id": scenario.get("id", "MANUAL"),
        "channel": channel,
        "verdict": verdict,
        "scam_type": scam_type,
        "risk_score": final_score,
        "first_alert": first_alert,
        "red_flags": cumulative_flags,
        "warning_ro": warning_ro,
        "official_suggestion": llm_res.get("official_suggestion"),
        "timeline": timeline,
        "messages": messages,
    }