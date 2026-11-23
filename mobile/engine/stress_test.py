import random
import time
from typing import List, Dict, Any
from engine import analyze_scenario

# Folosim un seed diferit pentru un set complet nou de 100 cazuri dinamice
random.seed(9991)

NAMES = ["Andrei", "Maria", "Vlad", "Ioana", "Mihai", "Elena", "Daria", "Cristian", "Alex", "Raluca"]
ROLES_FAMILY = ["mami", "mama", "tati", "tata", "bunico"]
AMOUNTS = ["350 lei", "800 lei", "1.450 lei", "2.100 lei", "3.200 lei", "550 RON"]
FEES = ["2,49 lei", "4,99 lei", "6,50 lei", "3,99 lei", "5,00 lei"]
PHONES = ["+40 721 441 902", "+40 744 812 309", "+40 755 190 884", "+40 766 502 119", "+40 731 998 201"]


def strip_diacritics(text: str) -> str:
    table = str.maketrans("ăâîșțĂÂÎȘȚ", "aaistAAIST")
    return text.translate(table)


def maybe_no_diacritics(text: str) -> str:
    # 35% șansă ca mesajul să fie scris fără diacritice (exact ca în mesajele reale de pe telefon)
    return strip_diacritics(text) if random.random() < 0.35 else text


def make_safe_case(idx: int) -> Dict[str, Any]:
    name = random.choice(NAMES)
    amount = random.choice(AMOUNTS)
    code = random.randint(100000, 999999)
    awb = random.randint(1000000, 9999999)

    variants = [
        # 1. Cod OTP bancar real (capcană de securitate)
        {
            "channel": "sms",
            "sender": {"name": "BancaDunarea", "address": "BancaDunarea", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"Banca Dunărea: Codul dvs. de confirmare pentru plata de {amount} este {code}. Nu comunicați acest cod nimănui, nici angajaților băncii."}],
        },
        # 2. Notificare bancară oficială fără cerere
        {
            "channel": "sms",
            "sender": {"name": "BancaDunarea", "address": "BancaDunarea", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"Banca Dunărea: Ați efectuat o plată cu cardul în valoare de {amount}. Detalii în aplicație sau pe bancadunarea.ro."}],
        },
        # 3. Curier legitim pe domeniu oficial cu ramburs 0
        {
            "channel": "sms",
            "sender": {"name": "CurierExpres", "address": "CurierExpres", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"CurierExpres: Coletul AWB {awb} va fi livrat astăzi. Ramburs: 0 lei. Urmărire pe curierexpres.ro/tracking"}],
        },
        # 4. ANAF informare oficială pe anaf.ro
        {
            "channel": "email",
            "sender": {"name": "ANAF", "address": "notificari@anaf.ro", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Stimate contribuabil, recipisa declarației depuse este disponibilă în contul dvs. pe anaf.ro."}],
        },
        # 5. MegaShop confirmare comandă oficială
        {
            "channel": "sms",
            "sender": {"name": "MegaShop", "address": "MegaShop", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"MegaShop: Comanda #{awb} a fost confirmată. Factura este disponibilă pe megashop.ro."}],
        },
        # 6. Conversație normală cu o rudă cunoscută (chiar dacă pomenește de cumpărături sau bani)
        {
            "channel": "whatsapp",
            "sender": {"name": name, "address": random.choice(PHONES), "known_contact": True},
            "messages": [
                {"n": 1, "from": "sender", "text": f"Bună! Trec pe la tine pe la 17:30, vrei să iau pâine și apă?"},
                {"n": 2, "from": "reader", "text": "Da, te rog, îți dau banii când ajungi."},
                {"n": 3, "from": "sender", "text": "Stai liniștită, ne vedem imediat!"},
            ],
        },
        # 7. Conversație scurtă prietenească cu emoji
        {
            "channel": "whatsapp",
            "sender": {"name": name, "address": random.choice(PHONES), "known_contact": True},
            "messages": [
                {"n": 1, "from": "sender", "text": "La mulți ani cu sănătate! 🎉🎂"},
                {"n": 2, "from": "reader", "text": "Mulțumesc frumos! ❤️"},
            ],
        },
        # 8. Întrebare legitimă pe marketplace (fără link extern și fără cerere de card)
        {
            "channel": "chat",
            "sender": {"name": f"Client_{random.randint(10,99)}", "address": f"usr_{random.randint(100,999)}", "known_contact": False},
            "messages": [
                {"n": 1, "from": "sender", "text": "Bună ziua! Mai este valabil anunțul? Putem stabili predare personală în oraș?"},
                {"n": 2, "from": "reader", "text": "Bună ziua, da, ne putem vedea mâine."},
            ],
        },
    ]

    chosen = random.choice(variants)
    msgs = []
    for m in chosen["messages"]:
        msgs.append({**m, "text": maybe_no_diacritics(m["text"])})

    return {
        "id": f"R{idx:03d}",
        "channel": chosen["channel"],
        "sender": dict(chosen["sender"]),
        "messages": msgs,
        "exp_verdict": "SAFE",
        "exp_type": "NONE",
        "exp_alert": None,
    }


def make_attack_case(idx: int) -> Dict[str, Any]:
    name = random.choice(NAMES)
    rel = random.choice(ROLES_FAMILY)
    amount = random.choice(AMOUNTS)
    fee = random.choice(FEES)
    phone = random.choice(PHONES)

    variants = [
        # 1. BANK_IMPERSONATION (SCAM)
        {
            "channel": "sms",
            "sender": {"name": "BancaDunarea", "address": "BancaDunarea", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Banca Dunărea: Contul dvs. a fost suspendat temporar. Reactivați accesul în 24h pe bancadunarea-securitate.com"}],
            "exp_verdict": "SCAM", "exp_type": "BANK_IMPERSONATION", "exp_alert": 1,
        },
        # 2. COURIER_FEE (SCAM)
        {
            "channel": "sms",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"CurierExpres: Livrarea coletului este blocată. Achitați taxa de {fee} urgent pe curierexpres-livrare.info"}],
            "exp_verdict": "SCAM", "exp_type": "COURIER_FEE", "exp_alert": 1,
        },
        # 3. FAMILY_EMERGENCY (thread 6 mesaje, alerta la 5)
        {
            "channel": "whatsapp",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [
                {"n": 1, "from": "sender", "text": f"Bună {rel}, mi s-a stricat telefonul, ăsta este numărul nou."},
                {"n": 2, "from": "reader", "text": "Cine este?"},
                {"n": 3, "from": "sender", "text": f"Sunt eu, {name}."},
                {"n": 4, "from": "reader", "text": "Bine, am notat."},
                {"n": 5, "from": "sender", "text": f"Am o urgență, îmi poți face tu un transfer de {amount} azi? Ți-i dau mâine."},
                {"n": 6, "from": "sender", "text": "Te rog să nu îi spui nimic lui tata."},
            ],
            "exp_verdict": "SCAM", "exp_type": "FAMILY_EMERGENCY", "exp_alert": 5,
        },
        # 4. TECH_SUPPORT (SCAM)
        {
            "channel": "call_transcript",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [
                {"n": 1, "from": "sender", "text": "Bună ziua, vă sunăm de la suportul tehnic. Telefonul dumneavoastră are un virus."},
                {"n": 2, "from": "reader", "text": "Și ce trebuie să fac?"},
                {"n": 3, "from": "sender", "text": "Descărcați TeamViewer ca să intrăm de la distanță să rezolvăm."},
            ],
            "exp_verdict": "SCAM", "exp_type": "TECH_SUPPORT", "exp_alert": 1,
        },
        # 5. MARKETPLACE (thread 3 mesaje, alerta la 3)
        {
            "channel": "chat",
            "sender": {"name": f"Cumparator_{random.randint(100,999)}", "address": "user_ext", "known_contact": False},
            "messages": [
                {"n": 1, "from": "sender", "text": "Bună ziua! Mai este disponibil anunțul?"},
                {"n": 2, "from": "reader", "text": "Da, este valabil."},
                {"n": 3, "from": "sender", "text": "Am plătit prin Livrare Sigură pe PiațaMea. Introduceți datele cardului pe piatamea-incasare.net urgent!"},
            ],
            "exp_verdict": "SCAM", "exp_type": "MARKETPLACE", "exp_alert": 3,
        },
        # 6. AUTHORITY_IMPERSONATION (SCAM)
        {
            "channel": "email",
            "sender": {"name": "ANAF Restituiri", "address": "rambursari@anaf-portal-ro.com", "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": f"ANAF: Stimate contribuabil, aveți o restituire de impozit de {amount}. Completați datele cardului în 24h pe anaf-portal-ro.com."}],
            "exp_verdict": "SCAM", "exp_type": "AUTHORITY_IMPERSONATION", "exp_alert": 1,
        },
        # 7. ACCOUNT_TAKEOVER (SCAM)
        {
            "channel": "whatsapp",
            "sender": {"name": name, "address": phone, "known_contact": True},
            "messages": [{"n": 1, "from": "sender", "text": "Salut! Am trimis din greșeală un cod de confirmare pe numărul tău prin SMS. Mi-l poți trimite aici urgent?"}],
            "exp_verdict": "SCAM", "exp_type": "ACCOUNT_TAKEOVER", "exp_alert": 1,
        },
        # 8. PRIZE_LOTTERY (SUSPICIOUS - 35p)
        {
            "channel": "sms",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Felicitări! Sunteți câștigătorul unui voucher la tombola MegaShop! Răspundeți cu DA pentru revendicare."}],
            "exp_verdict": "SUSPICIOUS", "exp_type": "PRIZE_LOTTERY", "exp_alert": 1,
        },
        # 9. JOB_OFFER (SUSPICIOUS - 45p)
        {
            "channel": "whatsapp",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Angajăm pentru lucru de acasă: câștigați 350 lei pe zi garantat! Achitați taxa de înscriere de 50 lei."}],
            "exp_verdict": "SUSPICIOUS", "exp_type": "JOB_OFFER", "exp_alert": 1,
        },
        # 10. INVESTMENT (SUSPICIOUS - 30p)
        {
            "channel": "whatsapp",
            "sender": {"name": None, "address": phone, "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Investiții în acțiuni cu profit garantat de 4.000 lei săptămânal! Hai să discutăm pe Telegram."}],
            "exp_verdict": "SUSPICIOUS", "exp_type": "INVESTMENT", "exp_alert": 1,
        },
        # 11. ROMANCE (SUSPICIOUS - 35p)
        {
            "channel": "chat",
            "sender": {"name": "Capt. Michael", "address": "michael_offshore", "known_contact": False},
            "messages": [
                {"n": 1, "from": "sender", "text": "Bună, mi-ar plăcea să te cunosc mai bine."},
                {"n": 2, "from": "reader", "text": "Bună, cu ce te ocupi?"},
                {"n": 3, "from": "sender", "text": f"Lucrez pe o platformă marină și vreau să vin la tine, dar am nevoie de {amount} pentru biletul de avion. Te implor ajută-mă!"},
            ],
            "exp_verdict": "SUSPICIOUS", "exp_type": "ROMANCE", "exp_alert": 3,
        },
    ]

    chosen = random.choice(variants)
    msgs = []
    for m in chosen["messages"]:
        msgs.append({**m, "text": maybe_no_diacritics(m["text"])})

    return {
        "id": f"R{idx:03d}",
        "channel": chosen["channel"],
        "sender": dict(chosen["sender"]),
        "messages": msgs,
        "exp_verdict": chosen["exp_verdict"],
        "exp_type": chosen["exp_type"],
        "exp_alert": chosen["exp_alert"],
    }


def generate_100_random_cases() -> List[Dict[str, Any]]:
    cases = [make_safe_case(i + 1) for i in range(40)] + [make_attack_case(41 + i) for i in range(60)]
    random.shuffle(cases)
    return cases


def run_stress_test():
    cases = generate_100_random_cases()
    print(f"Rulez stress-test randomizat pe {len(cases)} scenarii noi (40 SAFE + 60 SCAM/SUSPICIOUS)...\n")

    total = len(cases)
    verdict_ok = 0
    type_ok = 0
    alert_ok = 0
    false_positives = []
    false_negatives = []
    mismatches = []

    t0 = time.time()
    for c in cases:
        res = analyze_scenario(c)
        got_v, got_t, got_a = res["verdict"], res["scam_type"], res["first_alert"]
        exp_v, exp_t, exp_a = c["exp_verdict"], c["exp_type"], c["exp_alert"]

        if got_v == exp_v:
            verdict_ok += 1
        else:
            if exp_v == "SAFE" and got_v != "SAFE":
                false_positives.append((c["id"], got_v, res["red_flags"], c["messages"][-1]["text"]))
            elif exp_v != "SAFE" and got_v == "SAFE":
                false_negatives.append((c["id"], exp_v, exp_t, c["messages"][-1]["text"]))

        if got_t == exp_t:
            type_ok += 1
        if got_a == exp_a:
            alert_ok += 1

        if not (got_v == exp_v and got_t == exp_t and got_a == exp_a):
            mismatches.append((c["id"], got_v, exp_v, got_t, exp_t, got_a, exp_a, res["red_flags"], c["messages"][-1]["text"]))

    elapsed = time.time() - t0

    print("=" * 68)
    print(f"REZULTATE STRESS-TEST RANDOMIZAT (100 CAZURI) — {elapsed:.1f}s ({elapsed/total:.2f}s/caz)")
    print("=" * 68)
    print(f"✅ Verdict corect:     {verdict_ok}/{total} ({verdict_ok/total*100:.1f}%)")
    print(f"✅ Scam type corect:   {type_ok}/{total} ({type_ok/total*100:.1f}%)")
    print(f"✅ First alert corect: {alert_ok}/{total} ({alert_ok/total*100:.1f}%)")
    print(f"⚠️ False Positives (SAFE -> Alarmă): {len(false_positives)}")
    print(f"🚨 False Negatives (SCAM -> SAFE):   {len(false_negatives)}")
    print("=" * 68)

    if false_positives:
        print("\nDetalii False Positives:")
        for fp in false_positives[:5]:
            print(" ", fp)

    if false_negatives:
        print("\nDetalii False Negatives:")
        for fn in false_negatives[:5]:
            print(" ", fn)

    if mismatches:
        print(f"\nNepotriviri ({len(mismatches)}):")
        for m in mismatches[:10]:
            print(f"  {m[0]}: Got=({m[1]}, {m[3]}, alert={m[5]}) vs Exp=({m[2]}, {m[4]}, alert={m[6]}) | flags={m[7]} | msg={m[8][:60]}")


if __name__ == "__main__":
    run_stress_test()