"""Validation check: run every scenario file in a folder and compare with the expected CSV.

    python backend/evaluate.py                  # validation set, LLM on if LM Studio answers
    python backend/evaluate.py --no-llm         # rules + contacts only
    python backend/evaluate.py --selftest       # built-in Romanian hard cases (genuine traps, slow burns, no diacritics)
    python backend/evaluate.py --dir D --csv F  # another folder / answer key

Prints ids, labels, scores and flag codes only, never message text.
"""
import argparse
import csv
import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import fusion  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.abspath(os.path.join(_HERE, ".."))


def _load_csv(path):
    rows = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            rows[r["id"].strip()] = r
    return rows


def _fa(v):
    v = (v or "").strip()
    if not v:
        return None
    try:
        return int(v)
    except Exception:
        return v


def run_folder(folder, csv_path, use_llm):
    exp = _load_csv(csv_path) if csv_path and os.path.exists(csv_path) else {}
    files = sorted(glob.glob(os.path.join(folder, "*.json")))
    tot = {"verdict": 0, "type": 0, "alert": 0, "score": 0, "flags": 0}
    n = 0
    print(f"{'id':6} {'verdict':22} {'type':48} {'score':10} {'alert':10} flags")
    for fp in files:
        try:
            with open(fp, encoding="utf-8") as f:
                sc = json.load(f)
        except Exception as e:
            print(f"{os.path.basename(fp)}: cannot read ({type(e).__name__})")
            continue
        r = fusion.analyze(sc, use_llm=use_llm)
        sid = str(r.get("id") or os.path.splitext(os.path.basename(fp))[0])
        e = exp.get(sid)
        if not e:
            print(f"{sid:6} {r['verdict']:22} {r['scam_type']:48} {r['risk_score']:<10} {str(r['first_alert']):10} {';'.join(r['red_flags'])}")
            continue
        n += 1
        ok_v = r["verdict"] == e["verdict"].strip()
        ok_t = r["scam_type"] == e["scam_type"].strip()
        ok_a = r["first_alert"] == _fa(e["first_alert"])
        ok_s = str(r["risk_score"]) == e["risk_score"].strip()
        ef = {x for x in (e["red_flags"] or "").strip().split(";") if x}
        ok_f = set(r["red_flags"]) == ef
        for k, okk in (("verdict", ok_v), ("type", ok_t), ("alert", ok_a), ("score", ok_s), ("flags", ok_f)):
            tot[k] += okk
        m = lambda ok: " " if ok else "X"  # noqa: E731
        print(f"{sid:6} {m(ok_v)}{r['verdict']:10}/{e['verdict']:10} {m(ok_t)}{r['scam_type']:23}/{e['scam_type']:23} "
              f"{m(ok_s)}{r['risk_score']:>3}/{e['risk_score']:>4}  {m(ok_a)}{str(r['first_alert']):4}/{str(_fa(e['first_alert'])):4} "
              f"{m(ok_f)}{';'.join(r['red_flags'])}" + ("" if ok_f else f"  (expected {';'.join(sorted(ef))})"))
    llm = "on" if use_llm else "off"
    print(f"\nLLM {llm}. verdict {tot['verdict']}/{n}  type {tot['type']}/{n}  first_alert {tot['alert']}/{n}  "
          f"score {tot['score']}/{n}  flags {tot['flags']}/{n}")
    return tot, n


# ------------------------------------------------------------------------------------------------ self-test
# (id, channel, (name, address, known), [(from, text)], verdict, type, first_alert or (lo, hi) or None, must_have_flags)
U = (None, "+40 7xx xxx 101", False)
SELFTEST = [
    ("S01", "sms", U, [("sender", "BANCA DUNAREA: Am detectat o tranzactie suspecta pe cardul dvs. Confirmati datele cardului urgent pe bancadunarea-verificare.com")],
     "SCAM", "BANK_IMPERSONATION", 1, ["RF_SUSPICIOUS_CONTACT", "RF_DATA_REQUEST"]),
    ("S02", "call_transcript", (None, "+40 2xx xxx 555", False), [
        ("sender", "Buna ziua, sunt Mihai de la departamentul de fraude al bancii."),
        ("reader", "Da?"),
        ("sender", "Am observat o plata suspecta de 2.300 lei din contul dumneavoastra."),
        ("reader", "Nu am facut eu plata."),
        ("sender", "Ca sa o anulam, va rog sa-mi spuneti codul primit prin SMS.")],
     "SCAM", "BANK_IMPERSONATION", (3, 5), ["RF_CODE_REQUEST"]),
    ("S03", "sms", U, [("sender", "Coletul tau este retinut in depozit. Plateste taxa vamala de 9,50 lei aici: posta-colete.xyz pana azi")],
     "SCAM", "COURIER_FEE", 1, ["RF_PAYMENT_REQUEST", "RF_SUSPICIOUS_CONTACT"]),
    ("S04", "email", ("ANAF", "anaf.notificari@gmail.com", False), [
        ("sender", "Aveți o datorie la bugetul de stat. Plătiți amenda de 450 lei în 48 de ore pentru a evita executarea silită.")],
     "SCAM", "AUTHORITY_IMPERSONATION", 1, ["RF_PAYMENT_REQUEST", "RF_THREAT"]),
    ("S05", "whatsapp", U, [
        ("sender", "Buna bunico, sunt eu nepotul tau, am numar nou"),
        ("reader", "Tu esti Vlad?"),
        ("sender", "Da, eu sunt Vlad. Ce mai faci?"),
        ("reader", "Bine"),
        ("sender", "Am avut un accident cu masina si am nevoie urgent de 3000 lei pentru reparatie")],
     "SCAM", "FAMILY_EMERGENCY", 5, ["RF_NEW_NUMBER", "RF_PAYMENT_REQUEST", "RF_EMOTIONAL_PRESSURE"]),
    ("S06", "sms", U, [("sender", "Microsoft: Calculatorul dvs. este infectat. Sunati imediat si instalati TeamViewer.")],
     "SCAM", "TECH_SUPPORT", 1, ["RF_REMOTE_ACCESS"]),
    ("S07", "chat", ("Ionut", "user_5531", False), [
        ("sender", "Salut, mai e valabil anuntul cu canapeaua?"),
        ("reader", "Da"),
        ("sender", "Super, platesc acum prin curier. Ca sa primesti banii, completeaza datele cardului pe piatamea-livrare.net")],
     "SCAM", "MARKETPLACE", 3, ["RF_DATA_REQUEST"]),
    ("S08", "whatsapp", ("Ioana", "+40 7xx xxx 202", True), [
        ("sender", "Scuze, ti-a venit un cod de la WhatsApp din greseala, poti sa mi-l trimiti repede?")],
     "SCAM", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S09", "whatsapp", U, [
        ("sender", "Buna ziua, va prezint o platforma de investitii recomandata de experti."),
        ("reader", "Ce e?"),
        ("sender", "Profit garantat de 30% pe luna, fara risc. Depuneti doar 1000 lei ca sa incepeti. Oferta expira azi.")],
     "SCAM", "INVESTMENT", 3, ["RF_TOO_GOOD", "RF_PAYMENT_REQUEST"]),
    ("S10", "chat", ("Robert", "robert_84", False), [
        ("sender", "Buna Elena, ce mai faci azi?"),
        ("reader", "Bine, dar tu?"),
        ("sender", "Ma gandesc la tine mereu, draga mea."),
        ("reader", "Si eu"),
        ("sender", "Sunt pe o platforma petroliera, dar in curand vin sa te vad."),
        ("reader", "Abia astept"),
        ("sender", "Am o problema, mi-au blocat salariul si am nevoie de 2000 euro pentru biletul de avion. Te rog, numai tu ma poti ajuta."),
        ("sender", "Nu spune nimanui despre noi, inca.")],
     "SCAM", "ROMANCE", 7, ["RF_PAYMENT_REQUEST", "RF_SECRECY"]),
    ("S11", "whatsapp", U, [("sender", "Buna ziua! Oferim job part-time de acasa: castigi 300 lei pe zi dand like-uri pe YouTube. Scrie-mi pe Telegram: t.me/joburi_rapide")],
     "SCAM", "JOB_OFFER", 1, ["RF_TOO_GOOD", "RF_CHANNEL_SWITCH"]),
    ("S12", "sms", U, [("sender", "Felicitari! Ai castigat un voucher de 1000 lei la MegaShop. Revendica premiul in 24 de ore: megashop-premii.top")],
     "SCAM", "PRIZE_LOTTERY", 1, ["RF_TOO_GOOD", "RF_SUSPICIOUS_CONTACT"]),
    ("S13", "sms", U, [("sender", "ENEL: Factura restanta. Curentul va fi oprit in 2 ore. Plateste factura de 87 lei pe enel-plata.com")],
     "SCAM", "OTHER", 1, ["RF_PAYMENT_REQUEST"]),
    ("S14", "sms", ("BancaDunarea", "BancaDunarea", False), [
        ("sender", "BANCA DUNAREA: Codul tau de autentificare este 552190. Nu il da nimanui. Banca nu iti va cere niciodata acest cod.")],
     "SAFE", "NONE", None, []),
    ("S15", "sms", ("CurierExpres", "CurierExpres", False), [
        ("sender", "CurierExpres: coletul tau ajunge maine intre 9 si 13. Plata la livrare: 0 lei. Detalii: https://curierexpres.ro/urmarire")],
     "SAFE", "NONE", None, []),
    ("S16", "email", ("Banca Dunărea", "oferte@bancadunarea.ro", False), [
        ("sender", "Stimate client, descoperiți noul cont de economii cu dobândă de 5%. Detalii pe www.bancadunarea.ro/economii sau la 0800 100 200.")],
     "SAFE", "NONE", None, []),
    ("S17", "whatsapp", ("Andrei (fiul)", "+40 7xx xxx 303", True), [
        ("sender", "Mami, vin duminica la masa. Sa faci sarmale, te rog!"),
        ("reader", "Sigur, puiule"),
        ("sender", "Poti sa-mi trimiti si reteta de cozonac? Te pup")],
     "SAFE", "NONE", None, []),
    ("S18", "email", ("ANAF", "notificari@anaf.ro", False), [
        ("sender", "Stimate contribuabil, a fost emisă decizia de impunere pentru anul 2025. O puteți consulta în Spațiul Privat Virtual pe www.anaf.ro. Termen de plată: 25.05.")],
     "SAFE", "NONE", None, []),
    ("S19", "sms", U, [("sender", "Buna ziua, sunt instalatorul. Ajung la dvs. maine la ora 10 pentru centrala.")],
     "SAFE", "NONE", None, []),
    ("S20", "sms", ("MegaShop", "MegaShop", False), [
        ("sender", "MegaShop: Comanda ta 88123 a fost confirmata. Plata se face la livrare. Detalii la 0800 500 600.")],
     "SAFE", "NONE", None, []),
    ("S21", "call_transcript", (None, "+40 3xx xxx 404", False), [
        ("sender", "Bună ziua, vă sunăm de la Banca Dunărea, serviciul de securitate."),
        ("reader", "Da"),
        ("sender", "Contul dvs. a fost accesat de altcineva. Pentru protecție, instalați aplicația AnyDesk.")],
     "SCAM", "BANK_IMPERSONATION", 3, ["RF_REMOTE_ACCESS", "RF_THREAT"]),
    ("S22", "sms", U, [("sender", "Bunico, sunt la politie, am facut un accident. Trimite-mi 2000 lei si nu-i spune lui mama")],
     "SCAM", "FAMILY_EMERGENCY", 1, ["RF_PAYMENT_REQUEST", "RF_SECRECY", "RF_EMOTIONAL_PRESSURE"]),
    ("S23", "sms", ("BancaDunarea", "BancaDunarea", False), [
        ("sender", "BancaDunarea: Cardul tau a fost blocat preventiv dupa 3 introduceri gresite ale PIN-ului. Pentru deblocare suna la 0800 100 200.")],
     "SAFE", "NONE", None, []),
    ("S24", "sms", U, [("sender", "😀😀🙏")], "SAFE", "NONE", None, []),
    ("S25", "chat", ("Alex", "alex_12", False), [("sender", "Salut! Iti trimit un cod pe SMS pentru verificare, zi-mi te rog cele 6 cifre")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S26", "call_transcript", (None, "+40 2xx xxx 606", False), [
        ("sender", "Buna ziua, va contactam de la Casa de Pensii in legatura cu dosarul dvs."),
        ("reader", "Da"),
        ("sender", "Totul e in regula, doar actualizam evidenta."),
        ("reader", "Bine"),
        ("sender", "Aveti dreptul la o recalculare."),
        ("reader", "Adica?"),
        ("sender", "Pensia va creste cu 500 lei, vesti bune!"),
        ("reader", "Ce bine"),
        ("sender", "Spuneti-mi va rog seria si numarul de buletin si CNP-ul."),
        ("sender", "Nu discutati cu nimeni despre asta pana nu se finalizeaza.")],
     "SCAM", "AUTHORITY_IMPERSONATION", (7, 9), ["RF_DATA_REQUEST", "RF_SECRECY"]),
    ("S27", "chat", ("Suport", "support_01", False), [
        ("sender", "Sunt de la suport clienti PiataMea. Scrie-mi pe WhatsApp ca sa iti deblocam contul: wa.me/40700000000")],
     "SCAM", "MARKETPLACE", 1, ["RF_CHANNEL_SWITCH", "RF_SUSPICIOUS_CONTACT"]),
    ("S28", "sms", U, [("sender", "Politia Romana: Aveti o amenda neplatita. Trimiteti poza buletinului la politia-amenzi.info altfel veti fi cercetat penal")],
     "SCAM", "AUTHORITY_IMPERSONATION", 1, ["RF_DATA_REQUEST", "RF_THREAT"]),
    ("S29", "chat", ("Cumpărător PiațaMea", "buyer_1", False), [
        ("sender", "Buna, mai e bicicleta?"),
        ("reader", "Da"),
        ("sender", "Vin maine sa o vad, platesc cash la predare.")],
     "SAFE", "NONE", None, []),
    ("S30", "sms", U, [("sender", "")], "SAFE", "NONE", None, []),
    # --- regression cases from the demo conversations (watcher/demo): indirect code asks from saved contacts,
    # --- card-detail voucher with a link, plain reminder from an unknown sender domain
    ("S31", "whatsapp", ("Radu (fiul)", "+40 7xx xxx 311", True), [
        ("sender", "Mamă, mi-am schimbat telefonul și nu mai pot intra în contul de WhatsApp."),
        ("sender", "Ți-a venit pe SMS un cod din 6 cifre? Zi-mi-l repede, te rog, e urgent.")],
     "SCAM", "ACCOUNT_TAKEOVER", 2, ["RF_CODE_REQUEST"]),
    ("S32", "chat", ("Costel", "costel_v", True), [("sender", "Îți vine acum un cod pe SMS. Trimite-mi-l aici, repede, mă ajuți?")],
     "SCAM", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S33", "sms", ("Dan", "+40 7xx xxx 312", True), [("sender", "Ti-a venit un cod de la Google? Da-mi-l si mie, ca sa-mi recuperez contul")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S34", "chat", ("mihai.popa77", "mihai.popa77", True), [("sender", "Îți trimit un cod de verificare pe telefon. Cum îți vine, scrie-l aici, e doar pentru confirmare.")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S35", "whatsapp", ("Sorin", "+40 7xx xxx 313", True), [("sender", "Ți-a venit un SMS cu niște cifre? Ce scrie în el?")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 1, ["RF_CODE_REQUEST"]),
    ("S36", "sms", ("BancaDunarea", "BancaDunarea", False), [
        ("sender", "BANCA DUNAREA: Codul tau de verificare este 481516. Nu-l da nimanui, nici daca iti cere cineva.")],
     "SAFE", "NONE", None, []),
    ("S37", "whatsapp", ("Vecina Maria", "+40 7xx xxx 314", True), [("sender", "Ai primit un cod pe SMS? Nu mi-l da, nu-l spune nimănui!")],
     "SAFE", "NONE", None, []),
    ("S38", "chat", ("oferta_zilei_shop", None, False), [
        ("sender", "Felicitări! Ați câștigat un voucher de 1.000 lei la tragerea noastră."),
        ("sender", "Pentru a-l primi, introduceți datele cardului: voucher-castig.example/plata. Oferta expiră în 30 de minute!")],
     "SCAM", "PRIZE_LOTTERY", 2, ["RF_DATA_REQUEST", "RF_SUSPICIOUS_CONTACT"]),
    ("S39", "chat", ("Oferta", None, False), [
        ("sender", "Voucher de 300 lei! Pentru a-l activa, introduceți datele cardului dvs. la voucher-cadou.example/activare. Expiră în 2 ore.")],
     "SCAM", "PRIZE_LOTTERY", 1, ["RF_DATA_REQUEST", "RF_SUSPICIOUS_CONTACT"]),
    ("S40", "chat", ("Oferta", None, False), [
        ("sender", "Voucher 200 lei! Completați informațiile cardului bancar aici: https://oferta-voucher.example/x")],
     "SCAM", "OTHER", 1, ["RF_DATA_REQUEST", "RF_SUSPICIOUS_CONTACT"]),
    ("S41", "chat", ("Oferta", None, False), [
        ("sender", "Ați primit un voucher. Vă rugăm să introduceți numărul cardului, data expirării și CVV pe https://voucher-bonus.example/")],
     "SCAM", "OTHER", 1, ["RF_DATA_REQUEST", "RF_SUSPICIOUS_CONTACT"]),
    ("S42", "email", ("Clinica Sănătatea", "programari@clinica-sanatatea.example", False), [
        ("sender", "Bună ziua, vă confirmăm programarea de marți la ora 9:30. Vă rugăm să veniți pe nemâncate.")],
     "SAFE", "NONE", None, []),
    ("S43", "email", ("Clinica Sănătatea", "programari@clinica-sanatatea.example", True), [
        ("sender", "Bună ziua, vă confirmăm programarea de marți la ora 9:30. Vă rugăm să veniți pe nemâncate."),
        ("reader", "Mulțumesc, voi veni."),
        ("sender", "Vă așteptăm. O zi bună!")],
     "SAFE", "NONE", None, []),
    ("S44", "email", ("Cabinet Dr. Popescu", "cabinet@popescu-dental.net", False), [
        ("sender", "Vă reamintim controlul de joi, ora 10:00. Dacă nu puteți ajunge, sunați la recepție.")],
     "SAFE", "NONE", None, []),
]


def _mk(case):
    sid, ch, (nm, addr, known), msgs = case[:4]
    return {"id": sid, "channel": ch, "sender": {"name": nm, "address": addr, "known_contact": known},
            "messages": [{"n": i + 1, "from": f, "text": t} for i, (f, t) in enumerate(msgs)]}


def run_selftest(use_llm):
    ok_all = 0
    for case in SELFTEST:
        sid, _ch, _s, _m, ev, et, ea, must = case
        r = fusion.analyze(_mk(case), use_llm=use_llm)
        ok_v = r["verdict"] == ev
        ok_t = r["scam_type"] == et
        fa = r["first_alert"]
        ok_a = (fa is not None and ea[0] <= fa <= ea[1]) if isinstance(ea, tuple) else fa == ea
        ok_f = all(f in r["red_flags"] for f in must)
        good = ok_v and ok_t and ok_a and ok_f
        ok_all += good
        m = lambda ok: " " if ok else "X"  # noqa: E731
        print(f"{sid:5} {m(ok_v)}{r['verdict']:10}/{ev:10} {m(ok_t)}{r['scam_type']:23}/{et:23} {r['risk_score']:>3} "
              f"{m(ok_a)}{str(fa):4}/{str(ea):7} {m(ok_f)}{';'.join(r['red_flags'])}")
    # robustness: odd inputs must not raise and must keep the response shape
    odd = [None, {}, {"messages": "text only"}, {"messages": None}, {"messages": [None, 5, {"text": None}]},
           {"messages": [{"from": "sender", "text": "x" * 200000}]}, {"id": "Z", "sender": "x", "messages": [{"text": "🙂" * 500}]}]
    robust = 0
    for o in odd:
        try:
            r = fusion.analyze(o, use_llm=False)
            robust += all(k in r for k in ("verdict", "scam_type", "risk_score", "first_alert", "red_flags", "label",
                                           "warning", "per_message", "signals"))
        except Exception:
            pass
    tg = fusion.analyze(_mk(SELFTEST[16]), use_llm=False, trust_gate=True)
    tg2 = fusion.analyze(_mk(SELFTEST[7]), use_llm=False, trust_gate=True)
    gate_ok = tg["signals"]["skipped_by_trust_gate"] and not tg2["signals"]["skipped_by_trust_gate"] and tg2["verdict"] == "SCAM"
    # saved contacts asking for a code in indirect words must trip the trust gate (S31-S35) and give an account-takeover result
    for case in SELFTEST:
        if case[0] in ("S31", "S32", "S33", "S34", "S35"):
            g = fusion.analyze(_mk(case), use_llm=False, trust_gate=True)
            gate_ok = (gate_ok and not g["signals"]["skipped_by_trust_gate"] and g["scam_type"] == "ACCOUNT_TAKEOVER"
                       and "RF_CODE_REQUEST" in g["red_flags"])
    print(f"\nselftest {ok_all}/{len(SELFTEST)}  robustness {robust}/{len(odd)}  trust-gate {'ok' if gate_ok else 'FAIL'}")
    return ok_all


# ------------------------------------------------------------------------------------------------ red team
# Invented evasive scams + hard negatives (none taken from the validation set). Same tuple shape as SELFTEST minus
# must-flags: verdict / type may list alternatives with "|"; first_alert is an int, a (lo, hi) range or None.
# Split fixed up front: crc32(id) even -> DEV (used for diagnosis), odd -> HELD (only totals until --reveal).
RT = [
    # ---- evasive money asks
    ("R001", "whatsapp", U, [("sender", "Mami, sunt eu, am numar nou. Iti scriu de aici ca s-a stricat ala vechi."),
                             ("reader", "Ce s-a intamplat?"),
                             ("sender", "Am ramas in oras fara portofel, ma ajuti si tu cu ceva pentru un Uber pana acasa? Te iubesc mult")],
     "SCAM|SUSPICIOUS", "FAMILY_EMERGENCY", 3),
    ("R002", "sms", U, [("sender", "Buna, scuze ca deranjez, poti sa-mi trimiti ce poti, orice suma, pe Revolut la numarul asta? Iti dau inapoi saptamana viitoare")],
     "SUSPICIOUS", "OTHER", 1),
    ("R003", "whatsapp", U, [("sender", "Bunico, sunt Andrei, iti scriu de pe telefonul unui prieten. Imi trebuie un mic ajutor pentru bilet de tren, nu am cum sa ajung acasa. Nu-i spune lui mama, te rog")],
     "SCAM", "FAMILY_EMERGENCY", 1),
    ("R004", "sms", U, [("sender", "Mama, am nevoie de un card cadou Google Play de 200, poti lua unul de la magazin si sa-mi trimiti poza cu codul de pe spate? E urgent")],
     "SCAM", "FAMILY_EMERGENCY", 1),
    ("R005", "chat", ("Mihai_consultant", "mihai_invest", False), [("sender", "Pentru a activa contul de investitii trebuie sa cumparati un voucher paysafe de 500 lei si sa imi trimiteti cele 16 cifre")],
     "SCAM", "INVESTMENT", 1),
    ("R006", "sms", U, [("sender", "Va rugam sa platiti medicamentele mamei dumneavoastra, e internata la noi. Transferul il faceti pe PayPal catre asistenta, azi.")],
     "SCAM|SUSPICIOUS", "FAMILY_EMERGENCY|OTHER", 1),
    ("R007", "whatsapp", U, [("sender", "Salut, sunt colegul lui Vlad. El e la spital si mi-a zis sa va rog sa trimiteti ceva pentru chirie, el nu poate acum")],
     "SUSPICIOUS", "FAMILY_EMERGENCY|OTHER", 1),
    ("R008", "sms", U, [("sender", "Investeste doar o mie de lei in bitcoin prin mine si in o luna ai zece mii, garantat")],
     "SUSPICIOUS|SCAM", "INVESTMENT", 1),
    ("R009", "whatsapp", U, [("sender", "Pentru telefonul din anunt, trimite-mi doua sute cincizeci de lei pe Revolut si ti-l trimit prin curier maine")],
     "SUSPICIOUS", "MARKETPLACE|OTHER", 1),
    ("R048", "sms", U, [("sender", "Am ramas fara baterie si fara bani in gara, poti sa-mi alimentezi cartela? Sunt Ioana, de pe telefonul unei doamne")],
     "SUSPICIOUS", "FAMILY_EMERGENCY|OTHER", 1),
    ("R049", "whatsapp", U, [("sender", "Draga, poti sa-mi cumperi tu un card cadou Steam? Iti explic diseara de ce, te rog mult")],
     "SUSPICIOUS", "OTHER|ROMANCE", 1),
    ("R050", "sms", U, [("sender", "Mama, da-mi si mie te rog cat poti, pe contul lui Alex, ca al meu e blocat")],
     "SUSPICIOUS|SCAM", "FAMILY_EMERGENCY", 1),
    ("R051", "whatsapp", U, [("sender", "Bunico, poti sa treci pe la bancomat si sa scoti ceva? Vine un prieten de-al meu sa ia plicul")],
     "SUSPICIOUS|SCAM", "FAMILY_EMERGENCY", 1),
    ("R052", "sms", U, [("sender", "Va rog transferati contravaloarea in contul de mai jos pana la ora 18, altfel comanda se anuleaza")],
     "SCAM|SUSPICIOUS", "OTHER|MARKETPLACE", 1),
    ("R053", "whatsapp", U, [("sender", "Imi faci si mie o alimentare pe Revolut? Doar 50, iti dau maine")],
     "SUSPICIOUS", "OTHER", 1),
    ("R054", "chat", ("Bogdan", "bogdan_travel", False), [("sender", "Salut frumoaso, as vrea sa te scot la cina dar sunt blocat in aeroport. Ai putea acoperi tu taxa de viza? Te iubesc deja")],
     "SUSPICIOUS|SCAM", "ROMANCE", 1),
    ("R060", "whatsapp", U, [("sender", "Unchiule, sunt eu Radu, scriu de pe nr unui coleg. Poti sa-mi dai o mana de ajutor cu 300 de lei? Iti explic acasa")],
     "SUSPICIOUS|SCAM", "FAMILY_EMERGENCY", 1),
    ("R067", "whatsapp", U, [("sender", "Buna ziua, sunt de la banca. Ca sa va mutam economiile intr-un cont sigur, mergeti la bancomatul de Bitcoin din mall si depuneti numerarul")],
     "SUSPICIOUS|SCAM", "BANK_IMPERSONATION", 1),
    ("R068", "sms", U, [("sender", "Pentru deblocarea pensiei, cumparati un card paysafe de 100 lei de la tutungerie si trimiteti codul la acest numar")],
     "SCAM", "AUTHORITY_IMPERSONATION|OTHER|ACCOUNT_TAKEOVER", 1),
    ("R069", "whatsapp", U, [("sender", "Am nevoie de un mic imprumut pana la salariu, iti dau inapoi, nu te supara ca te rog")],
     "SUSPICIOUS", "OTHER", 1),
    ("R070", "chat", ("Sofia", "sofia_m", False), [("sender", "Iubitule, as vrea sa vin la tine dar biletul e scump... daca ai putea contribui si tu cu ceva, ar fi minunat ❤️")],
     "SUSPICIOUS", "ROMANCE", 1),
    ("R072", "whatsapp", U, [("sender", "Buna! Sunt nepotul doamnei Elena de la 2. Ea m-a rugat sa va cer 100 de lei pentru medicamente, va da inapoi luni")],
     "SUSPICIOUS", "OTHER|FAMILY_EMERGENCY", 1),
    ("R073", "sms", U, [("sender", "Buna, sunt eu, Cristina. Am pierdut portofelul, imi poti face o reincarcare de 50 la numarul asta? 🙏")],
     "SUSPICIOUS|SCAM", "FAMILY_EMERGENCY|OTHER", 1),
    # ---- photos of documents / cards, data
    ("R010", "sms", U, [("sender", "Banca Dunarea: pentru actualizarea datelor faceti o poza fata-verso cardului si trimiteti-o pe acest numar de WhatsApp")],
     "SCAM|SUSPICIOUS", "BANK_IMPERSONATION", 1),
    ("R011", "whatsapp", U, [("sender", "Buna ziua, pentru a primi coletul trimiteti-ne o fotografie cu buletinul, fata si verso")],
     "SUSPICIOUS", "COURIER_FEE", 1),
    ("R012", "chat", ("Cumparator", "buyer_19", False), [("sender", "Ca sa iti trimit banii pentru masa, fa o poza la card pe ambele parti si trimite-o aici")],
     "SUSPICIOUS", "MARKETPLACE", 1),
    ("R016", "sms", U, [("sender", "Sunt de la banca dvs. Spuneti-mi doar ultimele 4 cifre de pe spatele cardului si data de expirare, pentru verificare")],
     "SUSPICIOUS|SCAM", "BANK_IMPERSONATION", 1),
    ("R055", "sms", U, [("sender", "Spuneti-mi codul numeric personal si seria de buletin pentru a va trimite pachetul cu ajutorul de la primarie")],
     "SUSPICIOUS|SCAM", "AUTHORITY_IMPERSONATION|OTHER", 1),
    ("R057", "whatsapp", U, [("sender", "Va rog trimiteti-mi aici o poza cu cardul, doar fata, ca sa va virez banii pentru anuntul de pe OLX")],
     "SUSPICIOUS", "MARKETPLACE", 1),
    ("R059", "email", ("Departament Plati", "plati@megashop-refund.com", False), [("sender", "Stimate client, pentru rambursarea comenzii va rugam sa ne transmiteti datele de autentificare in internet banking.")],
     "SCAM|SUSPICIOUS", "OTHER|MARKETPLACE|BANK_IMPERSONATION", 1),
    ("R061", "sms", U, [("sender", "Trimiteti C.N.P. si s e r i a buletinului pt verificare")],
     "SUSPICIOUS", "OTHER|AUTHORITY_IMPERSONATION", 1),
    # ---- codes
    ("R013", "call_transcript", (None, "+40 2xx xxx 777", False), [
        ("sender", "Buna ziua, va sun de la banca, departamentul de fraude."), ("reader", "Da, spuneti."),
        ("sender", "Ati primit acum un mesaj pe telefon. Cititi-mi va rog ce scrie acolo, cifra cu cifra.")],
     "SCAM", "BANK_IMPERSONATION", 3),
    ("R014", "sms", U, [("sender", "Confirmati-ne va rog cifrele primite adineauri, ca sa finalizam rambursarea")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER|OTHER", 1),
    ("R015", "whatsapp", ("Elena", "+40 7xx xxx 950", True), [("sender", "Elena aici. Ti-a picat un mesaj cu sase cifre de la mine din greseala, mi le dictezi si mie?")],
     "SUSPICIOUS|SCAM", "ACCOUNT_TAKEOVER", 1),
    ("R036", "whatsapp", U, [("sender", "Salut, ti-a venit un sms de la mine?"), ("sender", "Codul pls")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 2),
    ("R041", "whatsapp", ("Gabi", "+40 7xx xxx 951", True), [
        ("sender", "Hei, ce faci? De mult nu am mai vorbit"), ("reader", "Bine, tu?"),
        ("sender", "Bine. Particip la un concurs si am nevoie de voturi."), ("reader", "Sigur, cum votez?"),
        ("sender", "Iti vine un sms cu un cod de la ei, imi trimiti poza cu mesajul?")],
     "SUSPICIOUS|SCAM", "ACCOUNT_TAKEOVER", 5),
    ("R056", "sms", U, [("sender", "Ati primit un sms cu un cod de la noi? Va rugam confirmati-l prin raspuns la acest mesaj")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER|BANK_IMPERSONATION|OTHER", 1),
    ("R071", "sms", U, [("sender", "Va rugam sa dictati operatorului cele 6 caractere primite pentru a anula comanda frauduloasa.")],
     "SUSPICIOUS|SCAM", "ACCOUNT_TAKEOVER|BANK_IMPERSONATION|OTHER", 1),
    # ---- remote access by name or by description
    ("R017", "sms", U, [("sender", "Pentru recuperarea banilor instalati aplicatia pe care v-o trimit acum prin link si dati-mi acces, ca sa va ajut eu de aici")],
     "SUSPICIOUS|SCAM", "TECH_SUPPORT", 1),
    ("R018", "call_transcript", (None, "+40 2xx xxx 778", False), [
        ("sender", "Buna ziua, suntem de la suportul tehnic, calculatorul dumneavoastra trimite erori."), ("reader", "Ce trebuie sa fac?"),
        ("sender", "Descarcati programul AnyDsk si spuneti-mi numarul de noua cifre care apare")],
     "SCAM", "TECH_SUPPORT", 3),
    ("R019", "whatsapp", U, [("sender", "Lasati-ma sa intru pe telefonul dvs ca sa va repar aplicatia bancii, apasati pe Accept cand apare cererea")],
     "SUSPICIOUS|SCAM", "TECH_SUPPORT", 1),
    ("R020", "sms", U, [("sender", "T3amV1ewer instalat? Dati-mi ID si parola ca sa ne conectam")],
     "SCAM", "TECH_SUPPORT", 1),
    ("R074", "whatsapp", U, [("sender", "Instalati va rog aplicatia de verificare de pe linkul primit si apasati Permite ca sa vad ce se intampla pe ecran")],
     "SUSPICIOUS|SCAM", "TECH_SUPPORT", 1),
    # ---- links described rather than pasted
    ("R021", "sms", U, [("sender", "Coletul dvs asteapta plata taxei. Cautati pe Google curier-livrare punct com si achitati acolo")],
     "SUSPICIOUS|SCAM", "COURIER_FEE", 1),
    ("R022", "sms", U, [("sender", "Banca Dunarea: contul va fi suspendat. Intrati pe site-ul din urmatorul mesaj si confirmati datele de logare")],
     "SCAM", "BANK_IMPERSONATION", 1),
    # ---- obfuscation
    ("R023", "sms", U, [("sender", "B@NCA DUN@REA: C0NTUL DVS A F0ST BL0CAT. TRIMITETI C0DUL PRIMIT PRIN SMS")],
     "SCAM", "BANK_IMPERSONATION", 1),
    ("R024", "sms", U, [("sender", "trimite-mi c o d u l din sms rpd")],
     "SUSPICIOUS|SCAM", "ACCOUNT_TAKEOVER", 1),
    ("R025", "whatsapp", U, [("sender", "mamiii sunt eu numar nou 📱 trimite 💸 te rog urgeeent 🙏")],
     "SCAM", "FAMILY_EMERGENCY", 1),
    ("R026", "sms", U, [("sender", "Ati c.a.s.t.i.g.a.t un iPhone! Achitati doar t.a.x.a de 9 lei")],
     "SUSPICIOUS|SCAM", "PRIZE_LOTTERY", 1),
    ("R027", "sms", U, [("sender", "URGENT!!! PLATITI AMENDA DE 300 LEI AZI ALTFEL DOSAR PENAL. POLITIA")],
     "SCAM", "AUTHORITY_IMPERSONATION", 1),
    ("R028", "chat", ("Mark", "mark_usa", False), [("sender", "hey dear, send me sum money pt bilet, i miss u so much, te iubesc")],
     "SUSPICIOUS", "ROMANCE", 1),
    ("R029", "sms", U, [("sender", "dc nu raspunzi? am nev de bn urgent, da-mi un semn")],
     "SUSPICIOUS", "OTHER", 1),
    ("R030", "sms", U, [("sender", "Pl@titi t@xa vamala de 4 lei: posta-ro-colet.top")],
     "SCAM", "COURIER_FEE", 1),
    ("R031", "whatsapp", U, [("sender", "c0dul de 6 cifre, il am nevoie acum, zi mi l")],
     "SCAM|SUSPICIOUS", "ACCOUNT_TAKEOVER", 1),
    ("R032", "sms", U, [("sender", "Pin-ul cardului ni-l confirmati?? e pt securitatea dvs, sunt de la banca")],
     "SUSPICIOUS|SCAM", "BANK_IMPERSONATION", 1),
    ("R033", "whatsapp", U, [("sender", "Bunicooo, am facut accident 😭😭 imi trebe bani de avocat, n-o spune la nimeni")],
     "SCAM", "FAMILY_EMERGENCY", 1),
    ("R034", "sms", U, [("sender", "ANAF: aveti de recuperat 1.240 lei. Pt rambursare scrieti nr cardului si data expirarii ca raspuns")],
     "SCAM", "AUTHORITY_IMPERSONATION", 1),
    ("R035", "sms", U, [("sender", "Pls install AnyDesk now, sunt de la Microsoft, PC-ul tau e virusat")],
     "SCAM", "TECH_SUPPORT", 1),
    ("R037", "sms", U, [("sender", "Revolut 300 lei, acum. Iti explic dupa.")],
     "SUSPICIOUS", "OTHER", 1),
    ("R058", "sms", U, [("sender", "Hello! Am o oportunitate: tu imi dai 1k, eu iti dau 3k in doua saptamani. Zero risc.")],
     "SUSPICIOUS|SCAM", "INVESTMENT", 1),
    ("R062", "sms", U, [("sender", "C0d-ul primit pe SMS il trimiti aici te rog, e de la mine")],
     "SUSPICIOUS", "ACCOUNT_TAKEOVER", 1),
    ("R063", "whatsapp", U, [("sender", "Bunicaa sunt eu nepotu, ma bagat politia la arest 😢 trb dat bani la un domn ca sa ma scoata, nu zice la nimeni")],
     "SCAM", "FAMILY_EMERGENCY", 1),
    ("R064", "sms", U, [("sender", "Aveti un colet blocat. Pentru eliberare: plata 2,99 lei -> c u r i e r - r o . i n f o")],
     "SUSPICIOUS|SCAM", "COURIER_FEE", 1),
    ("R065", "sms", U, [("sender", "PLATA URGENTA: v-am trimis nota de plata, achitati in max 2 ore sau se taie curentul")],
     "SCAM", "OTHER", 1),
    ("R066", "sms", U, [("sender", "Trimite-mi banii pe Revolut, @ndrei_x, rpd te rog")],
     "SUSPICIOUS", "OTHER", 1),
    # ---- slow-burn threads, late and indirect hook
    ("R038", "chat", ("Daniel", "daniel_sea", False), [
        ("sender", "Buna Maria, ma bucur ca ne-am cunoscut aici. Ce faci azi?"), ("reader", "Bine, la gradina."),
        ("sender", "Ce frumos. Eu sunt inginer pe un vapor, mereu departe de casa."), ("reader", "Trebuie sa fie greu."),
        ("sender", "Da, dar cand vorbesc cu tine uit de tot. Esti o femeie speciala."), ("reader", "Esti dragut."),
        ("sender", "Vreau sa vin sa te cunosc luna viitoare."),
        ("sender", "Doar ca vama mi-a retinut bagajul cu cadourile pentru tine si cer o taxa. Ma poti ajuta tu, ca eu n-am acces la cont de aici?")],
     "SUSPICIOUS|SCAM", "ROMANCE", 8),
    ("R039", "whatsapp", U, [
        ("sender", "Buna ziua, sunt Andreea, consultant financiar. Am vazut ca v-ati interesat de economii."), ("reader", "Da, putin."),
        ("sender", "Am clienti de varsta dumneavoastra care si-au marit pensia frumos."), ("reader", "Cum asa?"),
        ("sender", "Printr-o platforma pe care o administrez eu. Randamentele au fost de 20% lunar anul acesta."), ("reader", "Si ce trebuie sa fac?"),
        ("sender", "Doar sa deschideti un cont pe platforma, va ajut eu pas cu pas."),
        ("sender", "Pentru inceput, un depozit de doua mii de lei pe care il transferati in contul indicat de mine.")],
     "SUSPICIOUS|SCAM", "INVESTMENT", (5, 8)),
    ("R040", "whatsapp", U, [
        ("sender", "Buna tataie, eu sunt, Mihai. Mi-am luat telefon nou."), ("reader", "Salut Mihai!"),
        ("sender", "Ce mai faci? Ai fost la doctor?"), ("reader", "Da, toate bune."),
        ("sender", "Ma bucur. Am si eu o rugaminte."), ("reader", "Spune."),
        ("sender", "Trebuie sa platesc ceva pana diseara si n-am card la mine."),
        ("sender", "Imi poti trimite tu pe numarul asta de cont? Iti dau inapoi duminica.")],
     "SCAM|SUSPICIOUS", "FAMILY_EMERGENCY", (7, 8)),
    ("R042", "whatsapp", (None, "+39 3xx xxx 100", False), [
        ("sender", "Buongiorno draga mea, ai dormit bine?"), ("reader", "Da, multumesc."),
        ("sender", "Ma gandesc la tine in fiecare dimineata."), ("reader", "Si eu la tine."),
        ("sender", "Saptamana viitoare vreau sa iau avionul sa vin la tine."), ("reader", "Abia astept!"),
        ("sender", "Doar ca banca mea italiana mi-a blocat cardul temporar."),
        ("sender", "Daca ai putea sa imi iei tu biletul, ti-i dau inapoi cand ajung, iubirea mea.")],
     "SUSPICIOUS|SCAM", "ROMANCE", 8),
    ("R043", "chat", ("HR Recrutare", "hr_jobs", False), [
        ("sender", "Buna ziua, am gasit CV-ul dvs. Cautam colaboratori pentru evaluari de produse."), ("reader", "Ce presupune?"),
        ("sender", "Dati note la produse online, 2-3 ore pe zi, castigati 250 de lei pe zi."), ("reader", "Si cum incep?"),
        ("sender", "Prima sarcina e o comanda de proba, o platiti dvs si va returnam suma plus comision.")],
     "SUSPICIOUS|SCAM", "JOB_OFFER", 5),
    ("R044", "sms", U, [
        ("sender", "CurierExpres: coletul dvs nu a putut fi livrat."),
        ("sender", "Pentru reprogramare raspundeti cu numele, adresa completa si numarul cardului pentru taxa de 3 lei.")],
     "SCAM", "COURIER_FEE", 2),
    ("R045", "chat", ("Cumparator", "buyer_77", False), [
        ("sender", "Buna, mai aveti masina de cusut?"), ("reader", "Da"),
        ("sender", "O iau, pret final 400?"), ("reader", "Bine"),
        ("sender", "Am trimis plata prin aplicatia de livrare. Va vine un mesaj, apasati acolo si confirmati cu datele de pe card ca sa intre banii.")],
     "SUSPICIOUS|SCAM", "MARKETPLACE", 5),
    ("R046", "chat", ("Crypto Mentor", "cmentor", False), [
        ("sender", "Salut! Am vazut postarea ta despre economii."), ("reader", "Da"),
        ("sender", "Eu ajut oameni sa isi faca un venit din crypto."), ("reader", "Cum?"),
        ("sender", "Imi trimiti 100 de dolari in USDT si eu fac trade pentru tine. Saptamanal iti dau profitul.")],
     "SUSPICIOUS|SCAM", "INVESTMENT", 5),
    ("R047", "call_transcript", (None, "+40 2xx xxx 779", False), [
        ("sender", "Buna ziua, va sunam de la furnizorul de internet."), ("reader", "Da"),
        ("sender", "Avem semnale ca routerul dvs. a fost compromis."), ("reader", "Ce sa fac?"),
        ("sender", "Deschideti magazinul de aplicatii si cautati aplicatia de asistenta pe care v-o dictez, apoi imi cititi codul afisat.")],
     "SCAM|SUSPICIOUS", "TECH_SUPPORT", (3, 5)),
    # ---- hard negatives
    ("N01", "whatsapp", ("Ana (fiica)", "+40 7xx xxx 901", True), [("sender", "Mami, imi iei si mie paine cand treci pe la magazin? Iti dau banii diseara")], "SAFE", "NONE", None),
    ("N02", "whatsapp", ("Fratele Dan", "+40 7xx xxx 902", True), [("sender", "Ti-am trimis azi cei 200 de lei pe care ti-i datoram, verifica te rog.")], "SAFE", "NONE", None),
    ("N03", "sms", ("BancaDunarea", "BancaDunarea", False), [("sender", "BancaDunarea: Codul de confirmare pentru plata online este 448812. Nu comunicati acest cod nimanui.")], "SAFE", "NONE", None),
    ("N04", "sms", ("CurierExpres", "CurierExpres", False), [("sender", "CurierExpres: Coletul AWB 1234567 va fi livrat azi intre 12 si 16. Ramburs: 0 lei.")], "SAFE", "NONE", None),
    ("N05", "whatsapp", U, [("sender", "Buna, sunt Mihaela, colega ta de la cor. Acesta e numarul meu nou, il poti salva. Ne vedem joi la repetitie!")], "SAFE", "NONE", None),
    ("N06", "whatsapp", ("Ion", "+40 7xx xxx 903", True), [("sender", "Te iubesc, mama. Mi-e dor de tine, vin in weekend sa te vad.")], "SAFE", "NONE", None),
    ("N07", "sms", U, [("sender", "Ajung in 10 minute, sunt in trafic.")], "SAFE", "NONE", None),
    ("N08", "whatsapp", ("Vecinul Paul", "+40 7xx xxx 904", True), [("sender", "Azi la 5 trec sa iau cheile, ok?")], "SAFE", "NONE", None),
    ("N09", "sms", ("BancaDunarea", "BancaDunarea", False), [("sender", "BancaDunarea: Am observat o tranzactie neobisnuita pe card. Daca nu o recunoasteti, sunati la numarul de pe spatele cardului.")], "SAFE", "NONE", None),
    ("N10", "whatsapp", ("Maria vecina", "+40 7xx xxx 905", True), [("sender", "Imi dai te rog numarul instalatorului? Mi s-a stricat robinetul")], "SAFE", "NONE", None),
    ("N11", "whatsapp", ("Andrei (fiul)", "+40 7xx xxx 906", True), [("sender", "Mama, am platit eu factura la curent azi, nu mai trebuie sa te duci la posta.")], "SAFE", "NONE", None),
    ("N12", "sms", U, [("sender", "Buna ziua, sunt curierul de la CurierExpres, sunt la poarta, puteti iesi?")], "SAFE", "NONE", None),
    ("N13", "whatsapp", ("Elena", "+40 7xx xxx 907", True), [("sender", "Iti returnez maine imprumutul, multumesc mult ca m-ai ajutat!")], "SAFE", "NONE", None),
    ("N14", "sms", U, [("sender", "Reteta dvs. este gata, o puteti ridica de la farmacie azi pana la ora 20.")], "SAFE", "NONE", None),
    ("N15", "whatsapp", ("Tata", "+40 7xx xxx 908", True), [("sender", "Am ajuns acasa, totul e bine. Te sun diseara.")], "SAFE", "NONE", None),
    ("N16", "whatsapp", ("Ioana (nepoata)", "+40 7xx xxx 909", True), [("sender", "Bunico, imi trimiti te rog reteta de placinta cu mere? Vreau sa o fac azi")], "SAFE", "NONE", None),
    ("N17", "sms", ("MegaShop", "MegaShop", False), [("sender", "MegaShop: Plata de 349 lei pentru comanda 5521 a fost primita. Multumim!")], "SAFE", "NONE", None),
    ("N18", "whatsapp", ("Sotul", "+40 7xx xxx 910", True), [("sender", "Am luat eu biletele de tren pentru duminica, nu mai cumpara tu.")], "SAFE", "NONE", None),
    ("N19", "whatsapp", ("Fiul", "+40 7xx xxx 911", True), [("sender", "Mama, te rog ia-ti medicamentele la ora 8, sa nu uiti. Te iubesc")], "SAFE", "NONE", None),
    ("N20", "email", ("ANAF", "notificari@anaf.ro", False), [("sender", "Va informam ca declaratia unica a fost depusa cu succes. Nu este necesara nicio actiune.")], "SAFE", "NONE", None),
    ("N21", "whatsapp", ("Corina", "+40 7xx xxx 912", True), [("sender", "Te rog nu spune nimanui de petrecerea surpriza pentru tata, e sambata la 6!")], "SAFE", "NONE", None),
    ("N22", "sms", U, [("sender", "Buna ziua, va reamintim ca maine la ora 9 vine echipa pentru citirea apometrelor. Va rugam sa fiti acasa.")], "SAFE", "NONE", None),
    ("N23", "whatsapp", U, [("sender", "Mami mi-am schimbat numarul, asta e cel nou. Te sun diseara sa-ti explic. Nu-ti cer nimic, doar salveaza-l.")], "SAFE", "NONE", None),
    ("N24", "whatsapp", ("Ana", "+40 7xx xxx 913", True), [("sender", "Ce faci, draga mea? Mi-e dor de tine, hai la o cafea saptamana asta")], "SAFE", "NONE", None),
    ("N25", "sms", ("BancaDunarea", "BancaDunarea", False), [("sender", "BancaDunarea: Daca primiti apeluri in numele bancii care va cer coduri, inchideti si sunati la numarul de pe spatele cardului.")], "SAFE", "NONE", None),
    ("N26", "whatsapp", ("Dan", "+40 7xx xxx 914", True), [("sender", "Am pus benzina cu cardul tau, ti-am dat banii inapoi pe Revolut. Mersi!")], "SAFE", "NONE", None),
    ("N27", "sms", U, [("sender", "Buna ziua, va sun in 5 minute pentru programarea la service, ok?")], "SAFE", "NONE", None),
    ("N28", "whatsapp", ("Mama", "+40 7xx xxx 915", True), [("sender", "Iti las bani pe masa pentru paine si lapte, ia si niste oua")], "SAFE", "NONE", None),
    ("N29", "whatsapp", ("Fiica", "+40 7xx xxx 916", True), [("sender", "Am cumparat eu medicamentele pentru tine, ti le aduc diseara. Nu-mi da nimic.")], "SAFE", "NONE", None),
    ("N30", "whatsapp", ("Vlad (nepot)", "+40 7xx xxx 917", True), [
        ("sender", "Buna bunico! Ce faci?"), ("reader", "Bine puiule"), ("sender", "Vin sambata pe la tine cu Ana."), ("reader", "Ce bine!"),
        ("sender", "Sa nu-ti faci griji de mancare, aducem noi tot."), ("sender", "Ajungem pe la 12, te pup")], "SAFE", "NONE", None),
    ("N31", "chat", ("Gheorghe", "gheorghe_55", True), [
        ("sender", "Buna dimineata, draga mea. Ai dormit bine?"), ("reader", "Da"), ("sender", "Te iubesc. Diseara gatesc eu."), ("reader", "Bine"),
        ("sender", "Iau eu painea si vinul, nu cumpara tu nimic.")], "SAFE", "NONE", None),
    ("N32", "sms", ("CurierExpres", "CurierExpres", False), [("sender", "CurierExpres: Nu v-am gasit acasa. Reprogramati livrarea gratuit pe curierexpres.ro sau la 0800 300 400.")], "SAFE", "NONE", None),
    ("N33", "whatsapp", ("Colega Irina", "+40 7xx xxx 918", True), [("sender", "Am facut plata pentru excursie, 150 de lei, ti-am trimis si dovada.")], "SAFE", "NONE", None),
    ("N34", "sms", U, [("sender", "Am ajuns la poarta, deschideti va rog. Sunt de la gaze, pentru revizie.")], "SAFE", "NONE", None),
    ("N35", "whatsapp", ("Nepotul Luca", "+40 7xx xxx 919", True), [("sender", "Bunico, multumesc pentru bani de ziua mea! Mi-am luat o carte.")], "SAFE", "NONE", None),
    ("N36", "whatsapp", ("Fiul", "+40 7xx xxx 920", True), [("sender", "Mami, nu trimite bani nimanui care zice ca sunt eu. Daca ai dubii, suna-ma pe numarul vechi.")], "SAFE", "NONE", None),
    ("N37", "sms", U, [("sender", "Buna ziua, sunt asistenta de la cabinetul doctorului Ionescu. Va rugam sa aduceti buletinul si cardul de sanatate la consultatie, maine la 10.")], "SAFE", "NONE", None),
    ("N38", "whatsapp", ("Mama", "+40 7xx xxx 921", True), [("sender", "Imi spui te rog codul de la interfon? Am uitat si sunt jos")], "SAFE", "NONE", None),
    ("N39", "whatsapp", ("Sotia", "+40 7xx xxx 922", True), [("sender", "Cand ajungi acasa? Repede ca se raceste mancarea 😄")], "SAFE", "NONE", None),
    ("N40", "sms", ("BancaDunarea", "BancaDunarea", False), [("sender", "BancaDunarea: Rata lunara de 820 lei a fost debitata din contul dvs. Sold disponibil in aplicatie.")], "SAFE", "NONE", None),
    ("N41", "whatsapp", ("Fratele", "+40 7xx xxx 923", True), [("sender", "Poti sa ma ajuti sambata cu mutatul? Iti fac eu cinste cu o pizza")], "SAFE", "NONE", None),
    ("N42", "sms", U, [("sender", "Azi la 5 incepe slujba la biserica, va asteptam!")], "SAFE", "NONE", None),
    ("N43", "email", ("MegaShop", "comenzi@megashop.ro", False), [("sender", "Comanda dvs. a fost expediata. Urmariti coletul pe megashop.ro/comenzi.")], "SAFE", "NONE", None),
    ("N44", "whatsapp", ("Fiica", "+40 7xx xxx 924", True), [("sender", "Mama, iti trimit eu bani de taxi sa vii la noi duminica, nu-ti face griji")], "SAFE", "NONE", None),
    ("N45", "whatsapp", ("Prietena Rodica", "+40 7xx xxx 925", True), [("sender", "Ce poti sa aduci la petrecere? Eu fac salata, tu poate un desert?")], "SAFE", "NONE", None),
    ("N46", "sms", U, [("sender", "Buna ziua, va contactam de la cabinetul veterinar: cainele dvs. poate fi ridicat dupa ora 16.")], "SAFE", "NONE", None),
    ("N47", "whatsapp", ("Fiul", "+40 7xx xxx 926", True), [("sender", "Mami, mi-am pierdut telefonul ieri dar l-am gasit, totul e ok. Te pup")], "SAFE", "NONE", None),
    ("N48", "whatsapp", U, [("sender", "Buna doamna Ileana, sunt Sorina de la etajul 3, am numar nou."), ("reader", "A, buna Sorina"),
                            ("sender", "Va las cheia la administrator, cum am vorbit. O zi buna!")], "SAFE", "NONE", None),
]


_SP = lambda name: (name, "+40 7xx xxx 930", True)  # noqa: E731  saved contact
RT += [
    # ---- romance: online-only partner, a life that explains absence, love-bombing, late and indirect hook
    ("RM01", "chat", ("Daniel Weber", "daniel_w", False), [
        ("sender", "Buna seara, Ana? Sper ca nu am gresit numarul."), ("reader", "Nu sunt Ana."),
        ("sender", "Oh, scuze! Dar ce frumos scrieti. Eu sunt Daniel, inginer pe o platforma petroliera in Marea Nordului."), ("reader", "Imi pare bine."),
        ("sender", "Simt ca sunteti un suflet pereche, nu cred in coincidente."), ("reader", "Esti dragut."),
        ("sender", "Iubirea mea, contractul meu se termina si vreau sa vin la tine, dar firma imi tine salariul pana la final."),
        ("sender", "Daca m-ai putea ajuta cu biletul de avion, ti-l dau inapoi de cum aterizez.")],
     "SUSPICIOUS|SCAM", "ROMANCE", 8),
    ("RM02", "whatsapp", U, [
        ("sender", "Buna dimineata, draga mea. Aici e greu, dar mesajele tale ma tin in viata."), ("reader", "Ai grija de tine."),
        ("sender", "Sunt in misiune ONU de 8 luni, nu pot face video, e interzis in baza."), ("reader", "Inteleg."),
        ("sender", "Comandantul imi aproba permisia daca se plateste taxa de concediu. Eu nu am acces la bani aici."),
        ("sender", "Poti tu sa platesti taxa? Te rog, sotia mea, doar tu ma poti ajuta.")],
     "SUSPICIOUS|SCAM", "ROMANCE", (5, 6)),
    ("RM03", "chat", ("Mark_Doctor", "mark_md", False), [
        ("sender", "Buna Elena, ma bucur ca ne-am cunoscut pe grupul de gradinarit."), ("reader", "Si eu."),
        ("sender", "Sunt medic in Yemen cu o organizatie umanitara. Fiul meu e la internat in Anglia."), ("reader", "Ce greu."),
        ("sender", "Te iubesc, stiu ca e devreme, dar simt asta."), ("reader", "Ma emotionezi."),
        ("sender", "Fiul meu a fost internat de urgenta si spitalul cere plata azi. Cardul meu e blocat aici."),
        ("sender", "Poti trimite tu 2000 de euro? Nu le spune copiilor tai, ei nu ar intelege ce e intre noi.")],
     "SCAM", "ROMANCE", (7, 8)),
    ("RM04", "whatsapp", U, [
        ("sender", "Buna, cred ca am gresit numarul, o cautam pe doamna Ionescu."), ("reader", "Nu e aici."),
        ("sender", "Ce coincidenta frumoasa. Eu sunt Alex, traiesc in Singapore, lucrez in finante."), ("reader", "Interesant."),
        ("sender", "Draga mea, de cand vorbim zambesc mereu. Vreau un viitor cu tine."), ("reader", "Si eu tin la tine."),
        ("sender", "Vreau sa te invat ce fac eu, castigam impreuna 15% pe saptamana pe platforma mea, e sigur."),
        ("sender", "Depune doar 500 de euro prima data, iti arat eu pas cu pas pe Telegram.")],
     "SCAM|SUSPICIOUS", "ROMANCE", (7, 8)),
    ("RM05", "chat", ("Capitan John", "capt_john", False), [
        ("sender", "Buna ziua, frumoaso. Profilul tau m-a impresionat."), ("reader", "Multumesc."),
        ("sender", "Sunt capitan pe un vas comercial, mereu pe mare."), ("reader", "Frumoasa meserie."),
        ("sender", "Ti-am trimis un colet cu un cadou pentru tine, iubito, bijuterii si o scrisoare."),
        ("sender", "A ramas la vama si cer o taxa de eliberare de 1.800 lei. Ma ajuti sa o achiti, ca sa ajunga la tine?")],
     "SUSPICIOUS|SCAM", "ROMANCE", 6),
    ("RM06", "whatsapp", U, [
        ("sender", "Buna seara, Maria. Sunt Robert, vaduv, am o fetita de 7 ani."), ("reader", "Imi pare rau."),
        ("sender", "Tu esti raza mea de soare, sufletul meu pereche."), ("reader", "Esti dulce."),
        ("sender", "Fetita are ziua maine si eu sunt blocat pe santier in Dubai."),
        ("sender", "Poti sa iei doua carduri cadou Google Play si sa-mi scrii codurile? Ii fac o surpriza.")],
     "SCAM", "ROMANCE", 6),
    ("RM07", "chat", ("Sergiu", "sergiu_fish", False), [
        ("sender", "Buna, am vazut ca iti place pescuitul, si mie!"), ("reader", "Da"),
        ("sender", "Hai sa vorbim pe Telegram, aici ma deconecteaza mereu."), ("reader", "Bine."),
        ("sender", "Iubita mea, nu pot face video, camera e stricata, dar te simt aproape."),
        ("sender", "Am o mostenire de la tata blocata intr-o banca din Londra. Avocatul cere un comision ca sa o deblocheze."),
        ("sender", "Daca imi imprumuti tu suma, iti dau inapoi dublu cand se elibereaza. Nu spune nimanui.")],
     "SCAM", "ROMANCE", (6, 7)),
    ("RM08", "whatsapp", U, [
        ("sender", "Salut draga, ma gandesc la tine"), ("reader", "Si eu"),
        ("sender", "Ma numesc Paul, sunt militar in Siria"), ("reader", "Ai grija"),
        ("sender", "Iubire, imi trebuie bani de drum ca sa vin acasa la tine, 900 de euro, azi daca se poate"),
        ("sender", "Trimite pe Western Union, iti dau eu datele")],
     "SUSPICIOUS|SCAM", "ROMANCE", 5),
    ("RM09", "chat", ("Andrei_Oslo", "andrei_oslo", False), [
        ("sender", "Buna Carmen, ce mai faci azi?"), ("reader", "Bine."),
        ("sender", "Am visat ca ne plimbam pe malul marii impreuna."), ("reader", "Ce frumos."),
        ("sender", "Abia astept sa fim impreuna, sotia mea."), ("reader", "Si eu."),
        ("sender", "Am o mica problema cu actele de calatorie, trebuie platita o taxa la ambasada."),
        ("sender", "Ai putea sa ma ajuti tu de data asta? Te rog, doar o data.")],
     "SUSPICIOUS|SCAM", "ROMANCE", (7, 8)),
    ("RM10", "whatsapp", U, [
        ("sender", "Buna! Sunt Lin, din Hong Kong. Am primit numarul tau de la o prietena, sper ca nu deranjez."), ("reader", "Nu, salut."),
        ("sender", "Imi place sa vorbesc cu tine, esti atat de calda. Te pot numi iubita mea?"), ("reader", "Poate."),
        ("sender", "Unchiul meu e analist si imi da semnale de trading. Ieri am castigat 3.000 de dolari."), ("reader", "Wow."),
        ("sender", "Pentru viitorul nostru, deschide si tu un cont pe aplicatia pe care ti-o trimit. Pune 300 de euro, restul il fac eu."),
        ("sender", "Nu spune familiei, ei nu inteleg crypto si o sa ne strice planurile.")],
     "SUSPICIOUS|SCAM", "ROMANCE", (7, 8)),
    ("RM11", "chat", ("Michael Brown", "mbrown", False), [
        ("sender", "Buna seara, Doina. Iti multumesc pentru vorbele frumoase de ieri."), ("reader", "Cu placere."),
        ("sender", "Lucrez inginer pe contract in Nigeria, inca 2 luni."), ("reader", "Ai grija."),
        ("sender", "Te iubesc, esti tot ce am."),
        ("sender", "Am facut malarie si spitalul nu ma trateaza pana nu platesc. Nu am pe nimeni altcineva in afara de tine."),
        ("sender", "Trimite te rog orice suma poti, prin Revolut, azi.")],
     "SCAM|SUSPICIOUS", "ROMANCE", 7),
    ("RM12", "whatsapp", U, [
        ("sender", "Buna dimineata, scumpa mea! ☀️"), ("reader", "Buna dimineata"),
        ("sender", "Ti-am spus ca ma gandesc doar la tine?"), ("reader", "Da :)"),
        ("sender", "Saptamana viitoare termin contractul pe nava si zbor direct la tine."), ("reader", "Abia astept!"),
        ("sender", "Agentia de turism imi cere plata in lei si eu am doar dolari pe card."),
        ("sender", "Ma scoti tu din incurcatura cu biletul? Ti-i dau pe toti cand ajung, iubirea mea.")],
     "SUSPICIOUS|SCAM", "ROMANCE", 8),
    ("RM13", "chat", ("Viktor", "viktor_un", False), [
        ("sender", "Scuze, mesajul era pentru sora mea. Dar ma bucur ca te-am gasit."), ("reader", "Nicio problema."),
        ("sender", "Sunt sergent in misiune de pace. Nu am voie cu camera, de aceea nu pot face video."), ("reader", "Inteleg."),
        ("sender", "Iubito, vreau sa ma retrag si sa vin la tine pentru totdeauna."),
        ("sender", "Trebuie sa platesc taxa de eliberare din armata pana vineri, altfel raman inca un an. Ma ajuti cu ce poti?")],
     "SUSPICIOUS|SCAM", "ROMANCE", 6),
    ("RM14", "whatsapp", U, [
        ("sender", "Buna, Ion. Sunt Natalia, ne-am scris pe Facebook."), ("reader", "A, da."),
        ("sender", "Esti barbatul pe care l-am asteptat toata viata, sufletul meu pereche."), ("reader", "Ma flatezi."),
        ("sender", "Sa ramana intre noi ce vorbim, copiii tai nu ar intelege."), ("reader", "Bine."),
        ("sender", "Am nevoie de bani pentru viza ca sa vin la tine. Trimite-mi 1.500 lei, te rog, iubitule.")],
     "SCAM|SUSPICIOUS", "ROMANCE", 7),
    ("RM15", "chat", ("George_Engineer", "george_eng", False), [
        ("sender", "Buna Lucia, ce zi frumoasa, ca tine."), ("reader", "Multumesc!"),
        ("sender", "Ti-am trimis un pachet cu cadouri, iti va scrie firma de transport."), ("reader", "Nu trebuia!"),
        ("sender", "Pachetul a fost oprit la granita pentru taxe."),
        ("sender", "Firma iti va da un cont. Te rog depune acolo suma, eu iti dau inapoi tot, iubito.")],
     "SUSPICIOUS|SCAM", "ROMANCE", 6),
    ("RM16", "whatsapp", U, [
        ("sender", "Buna, frumoaso, ce ochi minunati ai in poza."), ("reader", "Multumesc"),
        ("sender", "Sunt pilot si zbor mult, dar vreau sa fiu cu tine."), ("reader", "Ok"),
        ("sender", "Ca sa-ti trimit un cadou scump, am nevoie de o poza cu buletinul tau si de datele cardului.")],
     "SUSPICIOUS|SCAM", "ROMANCE", 5),
    # ---- romance hard negatives: real spouses, children, grandchildren, a genuine new acquaintance
    ("RN01", "whatsapp", _SP("Sotul Mihai"), [("sender", "Mi-e dor de tine, iubito. Abia astept sa vin duminica."), ("reader", "Si eu, drum bun!"),
                                             ("sender", "Te iubesc. Iti aduc flori.")], "SAFE", "NONE", None),
    ("RN02", "whatsapp", _SP("Nepotul Andrei"), [("sender", "Bunico, te iubesc mult! Abia astept sa vin la tine de Craciun."), ("reader", "Si eu, puiule"),
                                                ("sender", "Imi faci si cozonacul ala bun? 😍")], "SAFE", "NONE", None),
    ("RN03", "whatsapp", _SP("Fiica Ana"), [("sender", "❤️")], "SAFE", "NONE", None),
    ("RN04", "chat", _SP("Sotia Elena"), [("sender", "Buna dimineata, sufletul meu."), ("reader", "Buna"),
                                         ("sender", "Iti las cafeaua facuta. Ia-ti si umbrela, ploua."), ("sender", "Te iubesc, ne vedem diseara.")], "SAFE", "NONE", None),
    ("RN05", "whatsapp", _SP("Fiul Radu"), [("sender", "Mama, mi-e tare dor de tine."), ("reader", "Si mie, cand vii?"),
                                           ("sender", "Vin sambata cu avionul, am luat deja biletul."), ("sender", "Ma iei tu de la aeroport? Ajung la 6.")], "SAFE", "NONE", None),
    ("RN06", "whatsapp", _SP("Iubitul Dan"), [("sender", "Ce faci, frumoaso?"), ("reader", "Bine"), ("sender", "Abia astept sa te vad, iubire."),
                                             ("reader", "Si eu"), ("sender", "Am luat eu biletele la teatru, te astept la 7."), ("sender", "Te iubesc!")], "SAFE", "NONE", None),
    ("RN07", "whatsapp", _SP("Sotul"), [("sender", "Iubito, imi pui te rog incarcatorul in geanta? L-am uitat. Te iubesc")], "SAFE", "NONE", None),
    ("RN08", "chat", _SP("Nepoata Ioana"), [("sender", "Buni, mi-e dor de tine! 🥰"), ("reader", "Si mie, draga mea"),
                                           ("sender", "Ti-am trimis pe WhatsApp pozele de la nunta, sa le vezi.")], "SAFE", "NONE", None),
    ("RN09", "chat", ("Ion_62", "ion_62", False), [("sender", "Buna, ma bucur ca ne-am cunoscut la clubul de dans."), ("reader", "Si eu"),
                                                  ("sender", "Mi-ar placea sa te cunosc mai bine, mergem la o cafea sambata?")], "SAFE", "NONE", None),
]


def _rt_half(sid):
    import zlib
    return "DEV" if zlib.crc32(sid.encode("ascii")) % 2 == 0 else "HELD"


def _rt_llm_cache(path):
    """Optional disk cache of LLM answers for the invented red-team texts only (keyed by prompt), so rule-only changes
    can be re-scored with the model on without re-querying the GPU. Never used for the validation set."""
    import hashlib
    if not path or fusion._llm is None:
        return
    try:
        with open(path, encoding="utf-8") as f:
            cache = json.load(f)
    except Exception:
        cache = {}
    orig = fusion._llm.analyze

    def cached(scenario):
        msgs = fusion._llm._clean_messages(scenario)
        key = hashlib.sha256((fusion._llm.SYSTEM_PROMPT + "\x00" + fusion._llm._build_user_prompt(scenario, msgs) + "\x00"
                              + fusion._llm._model()).encode("utf-8")).hexdigest()
        if key in cache:
            fusion._llm._TL.status = "ok" if cache[key] else "invalid_output"
            return cache[key]
        r = orig(scenario)
        if r is not None or fusion._llm.last_status() == "invalid_output":
            cache[key] = r
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cache, f)
        return r

    fusion._llm.analyze = cached


def run_redteam(use_llm, half="DEV", reveal=False, verbose=True, prefix=None):
    """half: DEV | HELD | ALL. HELD-OUT rows are printed only with reveal=True; totals always."""
    tot = {}
    for case in RT:
        sid, _ch, _s, _m, ev, et, ea = case
        if prefix and not any(sid.startswith(p) for p in prefix.split(",")):
            continue
        h = _rt_half(sid)
        if half != "ALL" and h != half:
            continue
        r = fusion.analyze(_mk(case), use_llm=use_llm)
        evs, ets = ev.split("|"), et.split("|")
        neg = ev == "SAFE"
        fa = r["first_alert"]
        ok_v = r["verdict"] in evs
        ok_t = r["scam_type"] in ets
        ok_a = (fa is not None and ea[0] <= fa <= ea[1]) if isinstance(ea, tuple) else fa == ea
        groups = [h] + ([h + "/romance"] if sid[:2] in ("RM", "RN") else [])
        for g in groups:
            _rt_count(tot, g, r, neg, ok_v, ok_t, ok_a, ea, fa)
        if verbose and (h == "DEV" or reveal):
            m = lambda ok: " " if ok else "X"  # noqa: E731
            print(f"{sid:5} {h:4} {m(ok_v)}{r['verdict']:10}/{ev:16} {m(ok_t)}{r['scam_type']:23}/{et[:30]:30} {r['risk_score']:>3} "
                  f"{m(ok_a)}{str(fa):4}/{str(ea):7} {';'.join(r['red_flags'])}"
                  + (f"  llm+{';'.join(c for c in r['signals']['llm'] if c not in r['signals']['rules'] + r['signals']['contacts'])}"
                     if use_llm else ""))
    print()
    for h in sorted(tot):
        t = tot[h]
        print(f"redteam {h:12} LLM {'on ' if use_llm else 'off'} n={t['n']} (scams {t['pos']}, negatives {t['neg']})  "
              f"verdict {t['verdict']}/{t['n']}  type {t['type']}/{t['n']}  first_alert {t['alert']}/{t['n']}  "
              f"missed(scam->SAFE) {t['missed']}/{t['pos']}  false_alarm {t['false_alarm']}/{t['neg']}  early_alert {t['early']}  "
              f"llm_used {t['llm_used']}/{t['n']}")
    return tot


def _rt_count(tot, h, r, neg, ok_v, ok_t, ok_a, ea, fa):
    t = tot.setdefault(h, {"n": 0, "neg": 0, "pos": 0, "verdict": 0, "type": 0, "alert": 0, "missed": 0, "false_alarm": 0,
                           "early": 0, "llm_used": 0})
    t["n"] += 1
    t["neg" if neg else "pos"] += 1
    t["verdict"] += ok_v
    t["type"] += ok_t
    t["alert"] += ok_a
    t["missed"] += (not neg and r["verdict"] == "SAFE")
    t["false_alarm"] += (neg and r["verdict"] != "SAFE")
    lo = ea[0] if isinstance(ea, tuple) else ea
    t["early"] += (not neg and fa is not None and lo is not None and fa < lo)
    t["llm_used"] += bool(r["signals"].get("llm_used"))


# ------------------------------------------------------------------------------------------------ teammate benchmark
RAUL_PATH = os.path.join(ROOT, "Nou Raul", "stress_test.py")


def run_raul(use_llm, path=RAUL_PATH):
    """Teammate's 100-case randomised benchmark (read-only file). It imports analyze_scenario from a module named
    `engine`; an in-memory one is installed that calls fusion.analyze. Prints ids, labels and flag codes only."""
    import collections
    import importlib.util
    import types
    eng = types.ModuleType("engine")
    eng.analyze_scenario = lambda sc: fusion.analyze(sc, use_llm=use_llm)
    sys.modules["engine"] = eng
    spec = importlib.util.spec_from_file_location("raul_stress_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    cases = mod.generate_100_random_cases()
    n = len(cases)
    ok = {"verdict": 0, "type": 0, "alert": 0}
    scam_safe = alarm_safe = 0
    patterns = collections.Counter()
    for c in cases:
        r = fusion.analyze(c, use_llm=use_llm)
        gv, gt, ga = r["verdict"], r["scam_type"], r["first_alert"]
        ev, et, ea = c["exp_verdict"], c["exp_type"], c["exp_alert"]
        ok["verdict"] += gv == ev
        ok["type"] += gt == et
        ok["alert"] += ga == ea
        scam_safe += ev != "SAFE" and gv == "SAFE"
        alarm_safe += ev == "SAFE" and gv != "SAFE"
        if (gv, gt, ga) != (ev, et, ea):
            patterns[(ev, et, ea, gv, gt, ga, ";".join(r["red_flags"]))] += 1
    print(f"raul LLM {'on' if use_llm else 'off'}: n={n}  verdict {ok['verdict']}/{n}  type {ok['type']}/{n}  "
          f"first_alert {ok['alert']}/{n}  scam->SAFE {scam_safe}  SAFE->alarm {alarm_safe}")
    for (ev, et, ea, gv, gt, ga, fl), k in sorted(patterns.items(), key=lambda x: -x[1]):
        print(f"  {k:3}x expected ({ev}, {et}, {ea}) got ({gv}, {gt}, {ga})  flags {fl}")
    return ok, n


# ------------------------------------------------------------------------------------------------ repeatability

def _fields(r):
    """Every part of a result that the dashboard shows; text is left out of the comparison key names only."""
    s = r.get("signals") or {}
    return {
        "verdict": r.get("verdict"), "scam_type": r.get("scam_type"), "risk_score": r.get("risk_score"),
        "first_alert": r.get("first_alert"), "red_flags": list(r.get("red_flags") or []),
        "new_flags": [(p.get("n"), list(p.get("new_flags") or [])) for p in r.get("per_message") or []],
        "highlights": [(p.get("n"), [(h.get("start"), h.get("end"), h.get("flag")) for h in p.get("highlights") or []])
                       for p in r.get("per_message") or []],
        "warning": r.get("warning"), "label": r.get("label"),
        "signals.rules": s.get("rules"), "signals.contacts": s.get("contacts"), "signals.llm": s.get("llm"),
        "signals.llm_used": s.get("llm_used"), "signals.llm_status": s.get("llm_status"),
        "signals.other": {k: v for k, v in s.items() if k not in ("rules", "contacts", "llm", "llm_used", "llm_status")},
    }


def run_repeat(items, times):
    """items: [(id, scenario)]. Run each `times` times with the LLM on; print ids and differing field names only."""
    same = 0
    no_llm_runs = 0
    for sid, sc in items:
        runs = [_fields(fusion.analyze(sc, use_llm=True)) for _ in range(times)]
        base = runs[0]
        diff = sorted({k for r in runs[1:] for k in base if r.get(k) != base[k]})
        used = sum(1 for r in runs if r["signals.llm_used"])
        no_llm_runs += times - used
        if not diff:
            same += 1
        print(f"{str(sid):6} {'identical' if not diff else 'DIFFERS: ' + ','.join(diff):40} llm_used {used}/{times}")
    print(f"\nrepeat x{times}: {same}/{len(items)} scenarios identical across runs; runs without LLM: {no_llm_runs}")
    return same, len(items)


def _folder_items(folder):
    out = []
    for fp in sorted(glob.glob(os.path.join(folder, "*.json"))):
        try:
            with open(fp, encoding="utf-8") as f:
                sc = json.load(f)
            out.append((sc.get("id") or os.path.splitext(os.path.basename(fp))[0], sc))
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=0, metavar="N",
                    help="run every scenario N times with the LLM on and report whether the results were identical")
    ap.add_argument("--dir", default=os.path.join(ROOT, "Cerinte", "validation_set"))
    ap.add_argument("--csv", default=os.path.join(ROOT, "Cerinte", "validation_expected_results.csv"))
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--redteam", action="store_true", help="invented evasive scams + hard negatives (DEV half by default)")
    ap.add_argument("--half", default="DEV", choices=["DEV", "HELD", "ALL"])
    ap.add_argument("--reveal", action="store_true", help="print HELD-OUT rows too (do this once, at the end)")
    ap.add_argument("--llm-cache", default=None, metavar="FILE", help="red team only: cache LLM answers in FILE")
    ap.add_argument("--prefix", default=None, help="red team only: run ids starting with these comma-separated prefixes (RM,RN = romance)")
    ap.add_argument("--raul", action="store_true", help="teammate's 100-case randomised benchmark (Nou Raul/stress_test.py)")
    a = ap.parse_args()
    if a.raul:
        run_raul(not a.no_llm)
        return
    if a.redteam:
        if not a.no_llm:
            _rt_llm_cache(a.llm_cache)
        run_redteam(not a.no_llm, a.half, a.reveal, prefix=a.prefix)
        return
    if a.repeat > 0:
        items = [(c[0], _mk(c)) for c in SELFTEST] if a.selftest else _folder_items(a.dir)
        run_repeat(items, a.repeat)
    elif a.selftest:
        run_selftest(not a.no_llm)
    else:
        run_folder(a.dir, a.csv, not a.no_llm)


if __name__ == "__main__":
    main()
