"""Synthetic Romanian training data for the Signal C fine-tune (labels correct by construction).

Every sender message is assembled from pieces; a piece is a phrase with an optional flag and an evidence span marked
[[like this]]. The evidence in the target is exactly that span, so it occurs verbatim in the message. Nothing here is
read from Cerinte/ or from the backend selftest. The prompt is built with backend/llm.py's own functions (imported,
never edited), so the model input is byte-identical to what the live detector sends.

Usage: python training/gen_data.py [--n 1300] [--seed 7]
Writes training/data/train.jsonl and training/data/dev.jsonl (+ stats.json). No message text is printed.
"""
import argparse
import json
import random
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
import llm  # noqa: E402  (imported, not modified)

OUT = Path(__file__).resolve().parent / "data"

# ------------------------------------------------------------------ slots
NAMES_M = ["Andrei", "Mihai", "Cosmin", "Radu", "Vlad", "Bogdan", "Sorin", "Dan", "Cătălin", "Florin"]
NAMES_F = ["Maria", "Ioana", "Elena", "Andreea", "Raluca", "Diana", "Gabriela", "Alina", "Simona", "Cristina"]
NAMES = NAMES_M + NAMES_F
READER_ADDR = ["mamă", "tată", "bunico", "bunicule", "tanti", "nene", "mămico", "tati"]
AMTS = ["300", "450", "700", "1.200", "1.800", "2.500", "3.000", "150", "89", "5.000", "620", "980"]
GIFT = ["Google Play", "Steam", "Amazon", "Apple", "Paysafecard", "Vodafone"]
PAYAPPS = ["Revolut", "PayPal", "Western Union", "MoneyGram", "Wise", "Skrill"]
CHAT = ["Telegram", "WhatsApp", "Signal", "Viber"]
ORGS = {  # official catalog (Cerinte/official_catalog.json): organisation -> website
    "Banca Dunărea": "bancadunarea.ro", "CurierExpres": "curierexpres.ro", "PiațaMea": "piatamea.ro",
    "MegaShop": "megashop.ro", "ANAF": "anaf.ro",
}
TLD_BAD = ["com", "top", "xyz", "info", "online", "site", "cc", "icu", "click", "link"]
SUFFIX = ["securitate", "verificare", "online", "login", "plata", "ro", "support", "livrare", "contul", "oferte"]
FAKE_ORGS = ["Banca Transilvană Plus", "Orange Curier", "Poșta Rapidă", "FanCurier Express", "Raiffeisen Safe", "Digi Premii"]
EMOJI = ["🙏", "😢", "❤️", "🙂", "😘", "🚨", "⚠️", "💶", "🎁", "🔒"]


def rr(a, n=1):
    return random.sample(a, n) if n > 1 else random.choice(a)


def fold(s):
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))


def slug(o):
    return re.sub(r"[^a-z]", "", fold(o).lower())


def lookalike(org=None):
    org = org or rr(list(ORGS))
    base = slug(org)
    r = random.random()
    if r < 0.18:
        return random.choice(["bit.ly", "tinyurl.com", "cutt.ly", "t.ly", "rb.gy"]) + "/" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=random.randint(5, 7)))
    if r < 0.40:  # misspelling
        b = list(base)
        i = random.randrange(1, len(b))
        b[i] = {"a": "4", "e": "3", "o": "0", "i": "1"}.get(b[i], b[i] + b[i])
        return "".join(b) + "." + random.choice(["ro", "com", "net", "top"])
    return base + random.choice(["-", ""]) + rr(SUFFIX) + "." + rr(TLD_BAD)


def gen_email(org=None):
    base = slug(org or rr(list(ORGS)))
    return rr(["suport", "office", "no-reply", "contact"]) + "@" + base + random.choice(["-", ""]) + rr(SUFFIX) + "." + rr(TLD_BAD)


def phone():
    return "07" + "".join(random.choices("0123456789", k=1)) + "".join(random.choices("0123456789", k=7))


def fill(t, d):
    return t.format(**d)


def slots(org=None):
    d = dict(amt=rr(AMTS), gift=rr(GIFT), app=rr(PAYAPPS), chat=rr(CHAT), rd=rr(READER_ADDR),
             org=org or rr(list(ORGS)), ph=phone(), code=str(random.randint(100000, 999999)),
             hd="".join(random.choices("abcdefghijklmnoprstuv", k=7)), nm=rr(NAMES), n2=rr(NAMES),
             hh=random.choice([14, 15, 16, 17, 18, 20]), hrs=random.choice([2, 3, 24, 48]))
    d["bad"] = lookalike(d["org"])
    d["official"] = ORGS.get(d["org"], "banca.ro")
    d["mail"] = gen_email(d["org"])
    return d


# ------------------------------------------------------------------ phrase families (flag -> phrases with [[evidence]])
F = {
    "RF_PAYMENT_REQUEST:formal": [
        "Te rog [[virează {amt} lei]] pe IBAN-ul pe care ți-l trimit.",
        "Trebuie să [[achiți taxa de {amt} lei]] ca să se elibereze coletul.",
        "Pentru deblocare, [[plătiți o amendă de {amt} lei]].",
        "[[Transferă-mi {amt} de lei]] azi, ți-i dau înapoi luni.",
        "[[Încarcă un card cadou {gift}]] și trimite-mi poza.",
        "Cumpără [[carduri {gift} de {amt} lei]], e mai simplu așa.",
        "[[Trimite plata pe {app}]], apoi rezolvăm.",
        "Trebuie [[un avans de {amt} lei]] ca să fii înscris.",
        "[[Achită o taxă de procesare]] și primești totul.",
        "Plătește [[taxa vamală prin {app}]], apoi pachetul pleacă.",
        "[[Depune o garanție de {amt} lei]] ca să rezervi.",
    ],
    "RF_PAYMENT_REQUEST:personal": [
        "Mi-ar trebui [[ceva bani de taxi]], nu mai am cash la mine.",
        "Poți să-mi [[plătești tu un Uber]] până la gară?",
        "Am nevoie de [[bani pentru biletul de autobuz]], altfel nu ajung acasă.",
        "Mă ajuți și tu cu [[chiria pe luna asta]]? Sunt la limită.",
        "[[Plătește-mi tu rețeta]] de la farmacie, ți-o dau înapoi.",
        "Te rog, [[un mic ajutor financiar]], știi că nu cer des.",
        "Mi-ar prinde bine [[un mic ajutor]] până la salariu.",
        "[[Trimite-mi pe {app}]] ce poți, restul rezolv eu.",
        "[[Pune-mi niște bani în cont]], te rog frumos.",
        "[[Plătește tu factura]] de la telefon, mi s-a blocat cardul.",
        "Am nevoie de [[bani pentru bilet]], zborul e mâine dimineață.",
        "Ajută-mă cu [[banii pentru medicamente]], sunt scumpe.",
        "Mi-e rușine să cer, dar [[mă ajuți cu bani de mâncare]]?",
        "[[Dă-mi și mie banii]] pentru transport, ajung și ți-i returnez.",
    ],
    "RF_CODE_REQUEST": [
        "[[Spune-mi codul]] pe care l-ai primit prin SMS.",
        "Ți-a ajuns un mesaj cu cifre? [[Dă-mi cele 6 cifre]], e pentru verificare.",
        "[[Citește-mi codul din SMS]] ca să anulăm tranzacția.",
        "Ți-am trimis un cod din greșeală, [[mi-l poți retrimite]]?",
        "[[Care e PIN-ul]] cardului ca să verific?",
        "[[Scrie-mi parola]] de la contul tău, o rezolv eu.",
        "Ți-a venit ceva pe telefon? [[Spune-mi cifrele]] din mesaj.",
        "[[Comunică-ne codul de confirmare]] primit acum.",
        "[[Trimite-mi codul de pe SMS]], altfel nu pot continua.",
        "Am nevoie de [[codul din mesajul de la bancă]].",
    ],
    "RF_DATA_REQUEST": [
        "[[Trimite-mi o poză cu buletinul]] ca să te înscriu.",
        "Ai putea să [[faci o fotografie la actul de identitate]], față și verso?",
        "Completează [[numărul cardului și data de expirare]].",
        "[[Scrie-mi CNP-ul]] pentru dosar.",
        "[[Datele cardului]] sunt necesare pentru confirmare.",
        "Am nevoie de [[o poză cu cartea ta de identitate]], pentru colet.",
        "Trimite [[un selfie cu buletinul în mână]] pentru verificare.",
        "Introdu [[numărul cardului și CVV-ul]] în formular.",
        "Pentru contract, [[trimite-mi seria și numărul de la buletin]].",
        "[[Confirmă-ți datele personale și bancare]] în formular.",
    ],
    "RF_REMOTE_ACCESS": [
        "[[Instalați aplicația AnyDesk]] ca să vă ajut.",
        "[[Descarcă TeamViewer]] și spune-mi ID-ul.",
        "[[Lasă-mă să preiau controlul telefonului]] pentru câteva minute.",
        "[[Partajează-ți ecranul]] ca să vedem ce nu merge.",
        "Instalează [[o aplicație de asistență la distanță]] și deschide-o.",
    ],
    "RF_SUSPICIOUS_CONTACT": [
        "Intră aici: [[{bad}]]",
        "Confirmă pe [[{bad}]]",
        "Detalii și plata la [[{bad}]]",
        "Scrie-ne la [[{mail}]]",
        "Formularul este la [[{bad}]]",
    ],
    "RF_NEW_NUMBER": [
        "[[Am schimbat numărul]], salvează-l pe ăsta.",
        "Sunt pe [[un număr nou]], telefonul vechi s-a stricat.",
        "Mi-am pierdut telefonul, [[scrie-mi de pe acest număr]].",
        "[[Ăsta e noul meu număr]], îl poți salva.",
        "Nu te speria, [[scriu de pe alt număr]].",
    ],
    "RF_SECRECY": [
        "[[Să nu spui nimănui]], te rog.",
        "[[Rămâne între noi]], da?",
        "[[Nu zice nimic la bancă]] dacă te întreabă.",
        "[[Nu le spune alor tăi]], se supără.",
        "[[Nu spune nimic familiei]] până rezolv.",
        "Te rog, [[să rămână secret]].",
    ],
    "RF_TOO_GOOD:prize": [
        "[[Ați câștigat {amt} lei]] la tragerea de azi!",
        "Ai un [[premiu de {amt} lei]] nerevendicat.",
        "Ofertă unică: [[iPhone gratuit]] pentru tine.",
        "[[Veți primi o rambursare neașteptată]] de la stat.",
        "[[Ai fost ales să primești o moștenire]] din străinătate.",
    ],
    "RF_TOO_GOOD:invest": [
        "[[Profit garantat de 20% pe lună]], fără risc.",
        "[[Dublăm suma investită]] în 7 zile.",
        "[[Randament garantat de 3% pe zi]], fără pierderi.",
    ],
    "RF_TOO_GOOD:job": [
        "[[Câștigi 500 lei pe zi]] lucrând de acasă.",
        "[[Salariu de 3000 de euro]] fără experiență.",
        "[[Venit garantat]] din primul weekend, de acasă.",
    ],
    "RF_IMPERSONATION": [
        "Sunt [[de la departamentul de securitate al {org}]].",
        "[[Echipa {org}]] vă anunță o problemă.",
        "Vă contactăm din partea [[{org}]].",
        "Sunt [[agent {org}]] și vă sun în legătură cu contul.",
        "Aici [[serviciul clienți {org}]].",
    ],
    "RF_URGENCY": [
        "Fă asta [[chiar acum]].",
        "[[În următoarele {hrs} ore]], altfel e prea târziu.",
        "[[Azi până la ora {hh}]], nu mai târziu.",
        "E [[urgent]], te rog.",
        "Aceasta este [[ultima șansă]].",
        "Răspunde [[imediat]].",
    ],
    "RF_THREAT": [
        "Altfel [[contul va fi blocat]].",
        "[[Veți fi dat în judecată]] dacă nu răspundeți.",
        "Se va declanșa [[executarea silită]].",
        "[[Vei pierde toate datele]] din cont.",
        "Riscați [[o amendă mare]] și dosar penal.",
    ],
    "RF_THREAT:parcel": [
        "Dacă nu plătiți, [[coletul va fi returnat]].",
        "Altfel [[coletul va fi distrus]].",
    ],
    "RF_EMOTIONAL_PRESSURE": [
        "[[Nu mă lăsa la greu]], ai doar tu grijă de mine.",
        "[[Dacă ții la mine]], fă asta pentru mine.",
        "[[Am încredere doar în tine]].",
        "[[Mi-e frică, sunt singur]] aici.",
        "[[Te iubesc și nu am pe nimeni altcineva]].",
        "[[Ești tot ce mi-a mai rămas]].",
        "[[Dacă m-ai iubi cu adevărat]] m-ai ajuta.",
        "Sunt disperat, [[nu mai am pe nimeni]].",
    ],
    "RF_CHANNEL_SWITCH": [
        "[[Scrie-mi pe {chat}]] la @{hd}.",
        "[[Hai pe {chat}]], aici nu merge bine.",
        "[[Sună-mă la {ph}]] când poți.",
        "[[Mutăm discuția pe {chat}]], e mai sigur.",
        "[[Contactează-mă pe {chat}]] la numărul {ph}.",
    ],
}

ROM_EXCUSE = ["Sunt inginer pe o platformă offshore, nu pot pleca încă.", "Sunt în armată, într-o misiune în străinătate.", "Sunt medic în afară, contract pe șase luni.",
              "Sunt căpitan pe un vas, avem semnal rar.", "Sunt văduv de trei ani și mi-e greu singur.", "Aș vrea să ne vedem, dar nu pot să plec acum de aici."]
RAPPORT = [
    "Salut, ce faci?", "Bună ziua!", "Sper că ești bine.", "Ce mai faci, ai mâncat?", "Cum a fost ziua ta?",
    "Mi-a plăcut mult poza ta de profil.", "Azi a fost soare la mine.", "Îmi place să povestesc cu tine.",
    "Lucrez pe platforme petrolifere, de aceea scriu rar.", "Am văzut că ai aceeași pasiune pentru grădinărit.",
    "Sunt văduv, am doi copii mari.", "Locuiesc în Germania de câțiva ani.", "Ți-am scris ieri, nu știu dacă ai văzut.",
    "Ce planuri ai pentru weekend?", "Mă gândesc mult la tine în ultima vreme.", "Am citit ce mi-ai scris, mulțumesc.",
    "Să vezi ce zi am avut azi.", "Sper să nu te deranjez.", "Bună seara, scuze de deranj.", "Mi-ai lipsit azi.",
]
READER = [
    "Cine ești?", "Ce s-a întâmplat?", "Bine, spune-mi.", "Nu înțeleg, explică-mi.", "Stai să mă gândesc.",
    "Ok.", "Bună, ce mai faci?", "Sunt la piață acum, vorbim mai târziu.", "Nu știu dacă e bine ce îmi ceri.",
    "Da, am primit un mesaj cu un cod, ce fac cu el?", "Am sunat la bancă și mi-au zis să am grijă cu banii.",
    "Pot să vorbesc cu fiica mea mai întâi?", "Cât costă?", "Mulțumesc, sunt bine.", "De unde ai numărul meu?",
    "Dar nu am bani acum.", "Bine, încerc.", "Ți-am scris ieri despre bani, dar nu mai contează.",
]

# keyword obfuscations (applied word-level, may hit evidence too: evidence is extracted after the transform)
LEET = {"bani": ["b@ni", "b4ni", "ban1", "b a n i", "ba.ni"], "codul": ["c0dul", "c o d u l", "cod.ul"], "cod": ["c0d", "c o d"],
        "card": ["c@rd", "c4rd", "c a r d"], "contul": ["c0ntul", "cont.ul"], "buletinul": ["buletin.ul", "bul3tinul"],
        "transfer": ["tr@nsfer", "tran$fer"], "urgent": ["urg3nt", "u r g e n t"], "plătește": ["pl@tește"], "plata": ["pl@ta"],
        "taxa": ["t@xa", "t.a.x.a"], "ajutor": ["@jutor", "ajut0r"], "parola": ["p@rola", "par0la"]}


def obfuscate(s, style):
    """style: set of transform names. Markers [[ ]] survive every transform; typos never touch the marked span."""
    if "nodia" in style:
        s = fold(s)
    if "leet" in style:
        def sub(m):
            w = m.group(0)
            k = fold(w).lower()
            return random.choice(LEET[k]) if k in LEET and random.random() < 0.8 else w
        s = re.sub(r"[A-Za-zăâîșțĂÂÎȘȚşţ]+", sub, s)
    if "lower" in style:
        s = s.lower()
    if "nopunct" in style:
        s = re.sub(r"[,!?]|\.(?=\s|$)", "", s) if random.random() < 0.7 else s.replace(",", "")
    if "typo" in style:
        parts = re.split(r"(\[\[.*?\]\])", s)
        for i in range(0, len(parts), 2):
            w = parts[i].split(" ")
            for j, x in enumerate(w):
                if len(x) > 4 and x.isalpha() and random.random() < 0.12:
                    k = random.randrange(1, len(x) - 2)
                    w[j] = x[:k] + x[k + 1] + x[k] + x[k + 2:]
            parts[i] = " ".join(w)
        s = "".join(parts)
    return s


def pick_style(heavy):
    if not heavy:
        return set()
    pool = ["nodia", "leet", "lower", "nopunct", "typo", "emoji", "emoji"]
    return set(random.sample(pool, random.randint(1, 3)))


# ------------------------------------------------------------------ message assembly
def P(text, flag=None):
    return (text, flag)


def pf(flag, d, sub=None):
    if ":" in flag:
        flag, sub = flag.split(":")
    key = flag + (":" + sub if sub else "")
    if key not in F:
        key = next(k for k in F if k.split(":")[0] == flag)
    return (fill(rr(F[key]), d), key.split(":")[0])


def build_message(pieces, style, used):
    """pieces: [(text_with_markers, flag|None)] -> (final_text, [flags dicts]). Flags already used earlier in the thread are
    kept as text but not labelled (rule 5: report a flag where it first appears)."""
    texts, flags = [], []
    for text, flag in pieces:
        t = obfuscate(text, style)
        m = re.search(r"\[\[(.*?)\]\]", t)
        if m:
            ev = m.group(1).strip()
            t = t.replace("[[", "").replace("]]", "")
            if flag and flag not in used and 5 <= len(ev) <= 80 and ev in t:
                used.add(flag)
                flags.append({"code": flag, "evidence": ev})
        texts.append(t)
    msg = " ".join(texts)
    if "emoji" in style and random.random() < 0.8:
        msg += " " + "".join(random.sample(EMOJI, random.randint(1, 3)))
    if "lower" in style:
        msg = msg.replace("  ", " ")
    return msg, flags


def thread_from(stages, meta, style, reader_p=0.55, first_reader=False):
    """stages: list of sender messages (each list of pieces). Reader replies are interleaved."""
    used, msgs, per, n = set(), [], [], 0
    for i, pieces in enumerate(stages):
        if (i > 0 or first_reader) and random.random() < reader_p:
            n += 1
            msgs.append({"n": n, "from": "reader", "text": rr(READER)})
        text, flags = build_message(pieces, style, used)
        n += 1
        msgs.append({"n": n, "from": "sender", "text": text})
        per.append({"n": n, "flags": flags})
    return msgs, per


def mk_example(msgs, per, meta, scam_type, claimed_org, person_name, kind):
    scenario = {"id": "T", "channel": meta["channel"],
                "sender": {"name": meta["name"], "address": meta["address"], "known_contact": meta["known"]},
                "messages": msgs}
    cm = llm._clean_messages(scenario)
    user = llm._build_user_prompt(scenario, cm)
    target = {"per_message": per, "scam_type": scam_type, "claimed_org": claimed_org, "person_name": person_name}
    for p in per:  # the evidence must literally occur in its message
        text = next(m["text"] for m in msgs if m["n"] == p["n"])
        for f in p["flags"]:
            assert f["evidence"] in text and 5 <= len(f["evidence"]) <= 80
    return {"messages": [{"role": "system", "content": llm.SYSTEM_PROMPT}, {"role": "user", "content": user}],
            "target": json.dumps(target, ensure_ascii=False, separators=(",", ":")), "kind": kind, "scam_type": scam_type}


# ------------------------------------------------------------------ scam story builders -> (stages, meta, type, org, name)
def hook_pos(n_stages, slow):
    return n_stages - 1 if slow else random.randint(0, min(1, n_stages - 1))


def build_family(slow):
    d = slots()
    n = random.randint(2, 7) if slow else random.randint(1, 4)
    h = hook_pos(n, slow)
    stages = []
    for i in range(n):
        if i < h:
            stages.append([P(rr(["Salut {rd}!", "Bună {rd}, sunt eu.", "{rd}, ești acolo?", "Bună {rd}, ce faci?"]).format(**d)), P(rr(RAPPORT[:3] + RAPPORT[12:14]))])
        elif i == h:
            ps = [pf("RF_NEW_NUMBER", d)] if random.random() < 0.7 else []
            ps += [P(rr(["Mi s-a întâmplat o belea.", "Am o problemă.", "Sunt într-o situație urâtă.", "Am rămas fără bani în oraș."]))]
            ps += [pf("RF_PAYMENT_REQUEST", d, "personal")]
            for fl in random.sample(["RF_SECRECY", "RF_URGENCY", "RF_EMOTIONAL_PRESSURE"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
        else:
            ps = [P(rr(["Ai văzut mesajul meu?", "Te rog răspunde-mi.", "Mă aștept la tine.", "Spune-mi dacă ai făcut-o."]))]
            for fl in random.sample(["RF_URGENCY", "RF_EMOTIONAL_PRESSURE", "RF_CHANNEL_SWITCH", "RF_SECRECY"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "sms", "whatsapp"]), name=rr(["Necunoscut", "Număr nou", phone()]), address=phone(), known=False)
    return stages, meta, "FAMILY_EMERGENCY", None, d["nm"] if random.random() < 0.3 else None


def build_takeover(slow):
    d = slots()
    n = random.randint(1, 4) if not slow else random.randint(3, 6)
    h = hook_pos(n, slow)
    stages = []
    for i in range(n):
        if i < h:
            stages.append([P(rr(["Salut, ce faci?", "Hei, ești pe aici?", "Ai un minut?", "Bună, sper că nu deranjez."]))])
        elif i == h:
            ps = [P(rr(["Am o rugăminte ciudată.", "Mi-am încurcat numărul când m-am logat.", "Scuze de deranj."])), pf("RF_CODE_REQUEST", d)]
            if random.random() < 0.6:
                ps.append(pf("RF_URGENCY", d))
            if random.random() < 0.3:
                ps.append(pf("RF_SECRECY", d))
            stages.append(ps)
        else:
            ps = [P("Hai, te rog.")]
            if random.random() < 0.5:
                ps.append(pf("RF_URGENCY", d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "sms"]), name=rr(NAMES), address=phone(), known=True)
    return stages, meta, "ACCOUNT_TAKEOVER", None, None


def build_romance(slow):
    d = slots()
    n = random.randint(6, 10) if slow else random.randint(2, 4)
    h = hook_pos(n, slow)
    stages = []
    hook_kinds = ["pay", "gift", "id", "app", "med", "ticket", "customs", "frozen", "crypto"]
    hk = rr(hook_kinds)
    for i in range(n):
        if i < h:
            ps = [P(rr(RAPPORT)), P(rr(RAPPORT + ROM_EXCUSE))]
            if i == 0:
                ps.insert(0, P("Mă numesc {nm}.".format(**d)) if random.random() < 0.5 else P(rr(["Salut frumoaso!", "Bună, dragă."])))
            stages.append(ps)
        elif i == h:
            ps = [P(rr(["Am o problemă la care nu am cum să te implic, dar…", "Sunt blocat într-o situație grea.", "Trebuie să-ți spun ceva."]))]
            if hk == "pay":
                ps.append(pf("RF_PAYMENT_REQUEST", d, "personal"))
            elif hk == "gift":
                ps.append(P("{x}".format(x=fill("[[Cumpără carduri {gift} de {amt} lei]], e singura variantă.", d)), "RF_PAYMENT_REQUEST"))
            elif hk == "id":
                ps.append(pf("RF_DATA_REQUEST", d))
            elif hk == "app":
                ps.append(P(fill("[[Trimite-mi pe {app}]] ce poți, te rog.", d), "RF_PAYMENT_REQUEST"))
            elif hk == "ticket":
                ps.append(P(fill("Vreau să vin la tine, dar [[mi-ar trebui biletul de avion]], am contul blocat.", d), "RF_PAYMENT_REQUEST"))
            elif hk == "customs":
                ps.append(P(fill("Ți-am trimis un colet cu cadouri, dar [[trebuie plătită taxa la vamă]] ca să-l primești.", d), "RF_PAYMENT_REQUEST"))
            elif hk == "frozen":
                ps.append(P(fill("Contul meu e înghețat și [[am nevoie de ajutorul tău cu o sumă]] până îl deblochez.", d), "RF_PAYMENT_REQUEST"))
            elif hk == "crypto":
                ps.append(P(fill("Te învăț eu să investești, [[pune niște bani pe platforma mea]], vezi cum cresc.", d), "RF_PAYMENT_REQUEST"))
                ps.append(pf("RF_TOO_GOOD", d, "invest"))
            else:
                ps.append(P(fill("Mi-ar trebui [[bani pentru tratamentul mamei]].", d), "RF_PAYMENT_REQUEST"))
            ps.append(pf("RF_EMOTIONAL_PRESSURE", d))
            for fl in random.sample(["RF_SECRECY", "RF_CHANNEL_SWITCH", "RF_URGENCY"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
        else:
            ps = [P(rr(["Mă gândesc la tine.", "Nu am cui să mai cer.", "Te aștept."]))]
            for fl in random.sample(["RF_EMOTIONAL_PRESSURE", "RF_URGENCY", "RF_CHANNEL_SWITCH", "RF_DATA_REQUEST"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "email", "sms"]), name=d["nm"], address=phone(), known=False)
    return stages, meta, "ROMANCE", None, d["nm"]


def impersonation(org_key, typ, extras, slow, bad_link=True, hook_flags=("RF_IMPERSONATION",)):
    d = slots(org_key)
    n = random.randint(1, 3) if not slow else random.randint(2, 4)
    stages = []
    for i in range(n):
        ps = []
        if i == 0:
            ps.append(pf("RF_IMPERSONATION", d))
            if slow and n > 1:
                ps.append(P(rr(["Doar vă informăm că există o situație.", "Vă rugăm să ne răspundeți."])))
                stages.append(ps)
                continue
        for fl in extras:
            if random.random() < 0.8 and (i == n - 1 or random.random() < 0.5):
                ps.append(pf(fl, d))
        if not ps:
            ps.append(P(rr(["Revenim cu detalii.", "Vă mulțumim pentru înțelegere."])))
        stages.append(ps)
    nm = d["nm"] if random.random() < 0.3 else None
    meta = dict(channel=rr(["sms", "email", "whatsapp"]), name=rr([slug(org_key).title() or "Info", org_key.replace(" ", ""), phone()]),
                address=rr([phone(), d["mail"]]), known=False)
    return stages, meta, typ, org_key, nm


def build_bank(slow):
    return impersonation("Banca Dunărea", "BANK_IMPERSONATION",
                         ["RF_CODE_REQUEST", "RF_DATA_REQUEST", "RF_SUSPICIOUS_CONTACT", "RF_URGENCY", "RF_THREAT"], slow)


def build_courier(slow):
    return impersonation("CurierExpres", "COURIER_FEE",
                         ["RF_PAYMENT_REQUEST", "RF_SUSPICIOUS_CONTACT", "RF_URGENCY", "RF_THREAT:parcel"], slow)


def build_authority(slow):
    return impersonation("ANAF", "AUTHORITY_IMPERSONATION",
                         ["RF_PAYMENT_REQUEST", "RF_THREAT", "RF_URGENCY", "RF_SUSPICIOUS_CONTACT", "RF_SECRECY"], slow)


def build_tech(slow):
    o = rr(["Banca Dunărea", "MegaShop", "Microsoft"])
    s = impersonation(o, "TECH_SUPPORT", ["RF_REMOTE_ACCESS", "RF_URGENCY", "RF_THREAT", "RF_DATA_REQUEST"], slow)
    return s


def build_market(slow):
    d = slots("PiațaMea")
    n = random.randint(2, 6) if slow else random.randint(1, 3)
    h = hook_pos(n, slow)
    stages = []
    for i in range(n):
        if i < h:
            stages.append([P(rr(["Bună, mai e disponibil anunțul?", "Sunt interesat de produs, e în stare bună?", "Pot să-l iau azi, sunt în drum."]))])
        elif i == h:
            ps = [P("Iau produsul, am trimis avans prin curier.")]
            ps.append(pf(rr(["RF_SUSPICIOUS_CONTACT", "RF_DATA_REQUEST", "RF_PAYMENT_REQUEST", "RF_CHANNEL_SWITCH"]), d))
            if random.random() < 0.6:
                ps.append(pf("RF_DATA_REQUEST", d))
            if random.random() < 0.4:
                ps.append(pf("RF_URGENCY", d))
            stages.append(ps)
        else:
            ps = [P("Spune-mi dacă ai făcut pasul.")]
            if random.random() < 0.5:
                ps.append(pf(rr(["RF_URGENCY", "RF_CHANNEL_SWITCH"]), d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "sms", "email"]), name=d["nm"], address=rr([phone(), d["mail"]]), known=False)
    return stages, meta, "MARKETPLACE", None, None


def build_invest(slow):
    d = slots()
    n = random.randint(2, 6) if slow else random.randint(1, 3)
    h = hook_pos(n, slow)
    stages = []
    for i in range(n):
        if i < h:
            stages.append([P(rr(["Bună, ai auzit de investițiile în criptomonede?", "Salut, un prieten ți-a dat numărul tău.", "Ai putea fi interesat de un venit în plus."]))])
        elif i == h:
            ps = [pf("RF_TOO_GOOD", d, "invest"), pf(rr(["RF_CHANNEL_SWITCH", "RF_SUSPICIOUS_CONTACT"]), d)]
            if random.random() < 0.7:
                ps.append(pf("RF_PAYMENT_REQUEST", d))
            if random.random() < 0.4:
                ps.append(pf("RF_URGENCY", d))
            stages.append(ps)
        else:
            ps = [P("Nu ratezi, locurile se termină.")]
            for fl in random.sample(["RF_URGENCY", "RF_PAYMENT_REQUEST", "RF_CHANNEL_SWITCH"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "sms", "email"]), name=d["nm"], address=rr([phone(), d["mail"]]), known=False)
    return stages, meta, "INVESTMENT", None, d["nm"] if random.random() < 0.4 else None


def build_job(slow):
    d = slots()
    n = random.randint(2, 6) if slow else random.randint(1, 3)
    h = hook_pos(n, slow)
    stages = []
    for i in range(n):
        if i < h:
            stages.append([P(rr(["Bună, avem un post disponibil pentru tine.", "Salut, ți-am văzut CV-ul online.", "Căutăm colaboratori de acasă."]))])
        elif i == h:
            ps = [pf("RF_TOO_GOOD", d, "job"), pf(rr(["RF_DATA_REQUEST", "RF_PAYMENT_REQUEST", "RF_CHANNEL_SWITCH"]), d)]
            if random.random() < 0.5:
                ps.append(pf("RF_URGENCY", d))
            stages.append(ps)
        else:
            ps = [P("Așteptăm confirmarea ta.")]
            for fl in random.sample(["RF_DATA_REQUEST", "RF_PAYMENT_REQUEST", "RF_URGENCY"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
    meta = dict(channel=rr(["whatsapp", "email"]), name=d["nm"], address=rr([phone(), d["mail"]]), known=False)
    return stages, meta, "JOB_OFFER", rr([None, None, rr(FAKE_ORGS)]), d["nm"] if random.random() < 0.5 else None


def build_prize(slow):
    d = slots()
    org = rr(["MegaShop", "MegaShop", "Digi Premii", "Orange Concurs"])
    n = random.randint(1, 3)
    stages = []
    for i in range(n):
        if i == 0:
            ps = [pf("RF_TOO_GOOD", d, "prize")]
            if random.random() < 0.5:
                ps.insert(0, P(fill("Felicitări de la [[{org}]]!", dict(d, org=org)).replace("[[", "").replace("]]", "")))
            ps.append(pf(rr(["RF_SUSPICIOUS_CONTACT", "RF_DATA_REQUEST", "RF_PAYMENT_REQUEST"]), d))
            if random.random() < 0.6:
                ps.append(pf("RF_URGENCY", d))
            stages.append(ps)
        else:
            ps = [P("Nu uitați să confirmați.")]
            for fl in random.sample(["RF_PAYMENT_REQUEST", "RF_DATA_REQUEST", "RF_URGENCY", "RF_THREAT"], random.randint(0, 2)):
                ps.append(pf(fl, d))
            stages.append(ps)
    meta = dict(channel=rr(["sms", "email"]), name=org.replace(" ", ""), address=rr([phone(), d["mail"]]), known=False)
    return stages, meta, "PRIZE_LOTTERY", org, None


SCAM_BUILDERS = [(build_family, 3), (build_takeover, 2), (build_romance, 7), (build_bank, 3), (build_courier, 2),
                 (build_authority, 2), (build_tech, 1.5), (build_market, 2), (build_invest, 2), (build_job, 2), (build_prize, 1.5)]


# ------------------------------------------------------------------ genuine hard negatives (no flags, NONE)
def neg_pool(d):
    o, off = d["org"], d["official"]
    return [
        [P(f"{o}: factura ta de {d['amt']} lei este disponibilă în contul de client, pe {off}.")],
        [P(f"Codul tău {o} este {d['code']}. Nu îl comunica nimănui, nici angajaților noștri.")],
        [P(f"Parola ta unică pentru autentificare este {d['code']}. Dacă nu ai cerut-o, ignoră mesajul.")],
        [P(f"Coletul tău ajunge mâine între 10 și 14. Îl poți urmări pe {ORGS['CurierExpres']}.")],
        [P(f"{o} nu vă va cere niciodată codul, parola sau datele cardului. Dacă primiți astfel de cereri, închideți.")],
        [P("Cardul tău expiră luna viitoare. Poți cere unul nou din aplicația oficială, când ai timp.")],
        [P(f"Reduceri de weekend la MegaShop. Vezi oferta pe {ORGS['MegaShop']}.")],
        [P("Doctorul te așteaptă azi la ora 16:00, vino cu zece minute mai devreme.")],
        [P("Am plătit eu taxiul, nu-ți face griji. Ne vedem la cină.")],
        [P("Am luat biletul de tren, ajung la 18:30. Mă iei de la gară?")],
        [P("Te iubesc, bunico, vin duminică la prânz. Gătești tu sarmale?")],
        [P("Mi-e dor de tine, e urât fără tine. Sună-mă diseară când ajungi acasă.")],
        [P("Atenție, azi dimineață a venit o inspecție, e urgent să strângi actele din hol.")],
        [P("Salut, sunt Ioana de la farmacie. Rețeta ta e gata, o poți ridica oricând până vineri.")],
        [P(f"Extras de cont pe luna aceasta este disponibil în aplicația {o}. Nu răspundeți la acest mesaj.")],
        [P("Chiria s-a plătit deja, ți-am trimis eu transferul de dimineață. Mulțumesc pentru răbdare!")],
        [P("Am rămas fără baterie, scuze. Sunt la unchiul, vin mai târziu.")],
        [P("Am văzut știrea: nu mai da nimănui codul primit prin SMS, sunt escrocherii. Ai grijă!")],
        [P("Ședința de bloc e joi la ora 18:00, la parter. Vă așteptăm cu toții.")],
        [P(f"Plata ta de {d['amt']} lei a fost primită. Îți mulțumim că ești client {o}.")],
        [P("Livrarea a fost reprogramată pentru mâine. Nu este nevoie de nicio acțiune din partea ta.")],
        [P("Poți să-mi aduci mâine rețeta de la medic? O las pe masă și o iei tu, nu e grabă.")],
        [P("Ne vedem la ora 5 în fața bisericii. Ia-ți și umbrela, plouă.")],
        [P(f"Contul tău ANAF a fost actualizat. Poți consulta situația fiscală pe {ORGS['ANAF']}, fără alte acțiuni.")],
        [P("Salut, ți-am trimis pozele de la nuntă pe e-mail. Spune-mi dacă ți-au ajuns.")],
        [P("Mi-e dor de tine, iubito. Sâmbătă sunt acasă, facem o cină împreună."), P("Te iubesc!")],
        [P("Te iubesc, scumpule. Ai luat medicamentele? Nu uita de ele, te rog.")],
        [P("Dragă, mi-a fost dor de tine toată săptămâna. Putem să ne vedem duminică la plimbare?")],
        [P("Mamă, îmi iei și mie o pâine când treci pe la magazin? Mulțumesc!")],
        [P("Bunicule, trec diseară pe la tine să-ți aduc ziarul și să-ți aranjez antena.")],
        [P(f"Am virat deja {d['amt']} lei pentru excursie, ți-am trimis și dovada pe {d['app']}.")],
        [P("Parola de la wifi-ul din cabană este 4829, ți-o las și pe frigider.")],
        [P(f"Codul de la interfon s-a schimbat, e {d['code'][:4]}. Doar să știi când vii.")],
        [P(f"Mamă, ăsta e noul meu număr, mi-am luat abonament la {d['org'].split()[0]}. Salvează-l, nu am nevoie de nimic.")],
        [P(f"Ajung în zece minute, ne vedem azi la {d['hh']-12 if d['hh']>12 else d['hh']}.")],
        [P("Pentru siguranța ta, dacă ai nelămuriri, sună la numărul de pe spatele cardului. Nu trebuie să faci nimic acum.")],
        [P(f"Ți-am returnat {d['amt']} lei în cont, să verifici că au ajuns. Pup!")],
        [P(f"Ți-am cumpărat biletul la film, ți-l dau când ne vedem. Te iubesc mult!")],
    ]


def build_negative(slow):
    d = slots()
    pool = neg_pool(d)
    n = random.randint(1, 3) if not slow else random.randint(3, 7)
    stages = [rr(pool) for _ in range(n)]
    known = random.random() < 0.55
    official = any(k in " ".join(t for s in stages for t, _ in s) for k in ("factura", "Codul tău", "Coletul", "Extras", "Reduceri", "ANAF", "nu vă va cere"))
    meta = dict(channel=rr(["sms", "whatsapp", "email"]), name=rr([d["nm"], d["org"].replace(" ", "")]), address=rr([phone(), d["mail"]]), known=known)
    claimed = None
    org_in = [k for k in ORGS if k in " ".join(t for s in stages for t, _ in s)]
    if org_in and official:
        claimed = org_in[0]
    return stages, meta, "NONE", claimed, None


def gen_one(i):
    if random.random() < 0.43:
        kind = "neg"
        stages, meta, typ, org, nm = build_negative(slow=random.random() < 0.3)
    else:
        kind = "scam"
        fns, ws = zip(*SCAM_BUILDERS)
        fn = random.choices(fns, weights=ws)[0]
        slow = random.random() < 0.35
        stages, meta, typ, org, nm = fn(slow)
        kind = "scam_slow" if slow else "scam"
    style = pick_style(random.random() < 0.45)
    msgs, per = thread_from(stages, meta, style, first_reader=random.random() < 0.2)
    ex = mk_example(msgs, per, meta, typ, org, nm, kind)
    ex["style"] = sorted(style)
    return ex


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1300)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    random.seed(a.seed)
    OUT.mkdir(exist_ok=True)
    seen, rows = set(), []
    while len(rows) < a.n:
        ex = gen_one(len(rows))
        key = ex["messages"][1]["content"]
        if key in seen:
            continue
        seen.add(key)
        rows.append(ex)
    random.shuffle(rows)
    k = max(1, len(rows) // 10)
    dev, train = rows[:k], rows[k:]
    for name, part in (("train", train), ("dev", dev)):
        with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in part:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    st = {"train": len(train), "dev": len(dev), "kinds": Counter(r["kind"] for r in rows), "types": Counter(r["scam_type"] for r in rows),
          "obfuscated": sum(1 for r in rows if r["style"]), "empty_flag_examples": sum(1 for r in rows if '"flags":[{' not in r["target"])}
    (OUT / "stats.json").write_text(json.dumps(st, indent=1), encoding="utf-8")
    print(json.dumps(st))


if __name__ == "__main__":
    main()
