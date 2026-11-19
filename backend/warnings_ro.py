"""Deterministic warnings, Romanian first (dumneavoastră), English second.

build(result, llm_extra) -> {"ro": str, "en": str}
At most three short sentences: what is happening, why, the one thing to do.
The action uses only an official channel: the catalog phone of the impersonated organisation, the number on the back of
the card, or the old number the reader already knows. Never a link, number or code from the analysed message.
"""
import re

try:
    from . import contacts
except ImportError:
    try:
        import contacts
    except Exception:
        contacts = None
except Exception:
    contacts = None

_MALE_A = {"Luca", "Mihnea", "Toma", "Horia", "Costea", "Sava", "Ilia", "Nicola", "Mircea", "Andrea"}

REASONS = [  # (flag, ro, en) in order of importance
    ("RF_REMOTE_ACCESS", "vă cere să instalați un program prin care un străin vă poate controla aparatul",
     "asks you to install a program that lets a stranger control your device"),
    ("RF_CODE_REQUEST", "vă cere un cod primit prin SMS", "asks for a code you received by SMS"),
    ("RF_DATA_REQUEST", "vă cere datele cardului sau date personale", "asks for your card or personal details"),
    ("RF_PAYMENT_REQUEST", "vă cere bani", "asks you for money"),
    ("RF_SUSPICIOUS_CONTACT", "trimite o adresă de internet falsă", "sends a fake web address"),
    ("RF_SECRECY", "vă cere să păstrați secretul", "asks you to keep it secret"),
    ("RF_TOO_GOOD", "vă promite bani sau premii prea frumoase ca să fie adevărate", "promises money or prizes that are too good to be true"),
    ("RF_THREAT", "încearcă să vă sperie", "tries to frighten you"),
    ("RF_URGENCY", "vă grăbește", "rushes you"),
    ("RF_CHANNEL_SWITCH", "vă cere să mutați discuția în altă aplicație", "asks you to move the chat to another app"),
    ("RF_NEW_NUMBER", "scrie de pe un număr nou", "writes from a new number"),
    ("RF_EMOTIONAL_PRESSURE", "încearcă să vă emoționeze", "plays on your feelings"),
]


def _reasons(flags, skip=(), k=2):
    ro, en = [], []
    for code, r, e in REASONS:
        if code in flags and code not in skip:
            ro.append(r)
            en.append(e)
        if len(ro) >= k:
            break
    if not ro:
        return "nu vine pe un canal oficial", "does not come through an official channel"
    return " și ".join(ro), " and ".join(en)


def _phone(org):
    try:
        info = contacts.org_info(org) if (contacts and org) else None
        return (info or {}).get("phone")
    except Exception:
        return None


def _female(name):
    return bool(name) and name.endswith("a") and name not in _MALE_A


def _clean_name(n):
    if not isinstance(n, str):
        return None
    n = re.sub(r"\(.*?\)", "", n).strip()
    m = re.match(r"([A-ZĂÂÎȘŞȚŢ][a-zăâîșşțţ]{2,})", n)
    return m.group(1) if m else None


def _authority_name(folded):
    if re.search(r"casa (?:nationala )?de pensii|casei de pensii", folded):
        return "Casa de Pensii", "the Pension Office"
    if re.search(r"politi", folded):
        return "Poliția", "the Police"
    if re.search(r"\banaf\b", folded):
        return "ANAF", "ANAF"
    return "o instituție a statului", "a state institution"


def build(result, llm_extra=None):
    try:
        return _build(result if isinstance(result, dict) else {}, llm_extra if isinstance(llm_extra, dict) else {})
    except Exception:
        return {"ro": "Atenție, verificați înainte să răspundeți. Nu trimiteți bani, coduri sau date până nu verificați la un număr cunoscut.",
                "en": "Careful, check before you reply. Do not send money, codes or details until you check on a number you know."}


def _build(r, x):
    verdict = r.get("verdict") or "SAFE"
    st = r.get("scam_type") or "NONE"
    flags = set(r.get("red_flags") or [])
    call = (r.get("channel") == "call_transcript")
    folded = " ".join(x.get("sender_texts_folded") or [])
    org = x.get("catalog_org") or None
    phone = _phone(org)
    person = x.get("person_name")

    if verdict == "SAFE":
        return {"ro": "Pare în regulă. Nu am găsit semne de țeapă: nu vi se cer bani, coduri sau date. "
                      "Dacă totuși aveți o îndoială, întrebați pe cineva de încredere înainte să răspundeți.",
                "en": "Looks fine. We found no signs of a scam: nobody is asking for money, codes or details. "
                      "If you still have a doubt, ask someone you trust before you reply."}

    if verdict == "SCAM":
        h_ro, h_en = "Atenție, pare o țeapă!", "Careful, this looks like a scam!"
    else:
        h_ro, h_en = "Atenție, verificați înainte să răspundeți.", "Careful, check before you reply."
    why_ro, why_en = _reasons(flags)
    stop_ro = "Închideți apelul" if call else "Nu apăsați pe nimic"
    who_ro = "Cineva se dă drept" if call else "Mesajul se dă drept"
    who_en = "Someone is pretending to be" if call else "The message pretends to be"
    stop_en = "Hang up" if call else "Do not tap anything"

    if st == "FAMILY_EMERGENCY":
        if re.search(r"\b(?:bunic\w*|buni|mamaie|tataie)\b", folded):
            rel_ro, rel_en, who_ro, who_en = "nepotul dumneavoastră", "your grandchild", "nepotul", "your grandchild"
        elif re.search(r"\b(?:mami|mama|mamico|mamica|tati|tata|taticule)\b", folded):
            rel_ro, rel_en, who_ro, who_en = "copilul dumneavoastră", "your child", "copilul", "your child"
        else:
            rel_ro, rel_en, who_ro, who_en = "o persoană dragă", "someone close to you", "persoana", "that person"
        if "RF_PAYMENT_REQUEST" in flags:
            ask_ro, ask_en = "cere bani", "asks for money"
        elif "RF_CODE_REQUEST" in flags:
            ask_ro, ask_en = "cere un cod", "asks for a code"
        elif "RF_DATA_REQUEST" in flags:
            ask_ro, ask_en = "cere date personale", "asks for personal details"
        else:
            ask_ro, ask_en = "vă cere ajutorul", "asks for help"
        if "RF_URGENCY" in flags:
            ask_ro += " urgent"
            ask_en += " urgently"
        if "RF_SECRECY" in flags:
            ask_ro += ", în secret"
            ask_en += ", in secret"
        src_ro = "Cineva de pe un număr nou" if "RF_NEW_NUMBER" in flags else "Cineva"
        src_en = "Someone on a new number" if "RF_NEW_NUMBER" in flags else "Someone"
        dont_ro = "Nu trimiteți bani" if "RF_PAYMENT_REQUEST" in flags else "Nu trimiteți nimic"
        dont_en = "Do not send money" if "RF_PAYMENT_REQUEST" in flags else "Do not send anything"
        if person:
            if _female(person):
                act_ro = f"sunați-o pe {person} la numărul ei vechi, pe care îl cunoașteți"
                act_en = f"call {person} on her old number, the one you know"
            else:
                act_ro = f"sunați-l pe {person} la numărul lui vechi, pe care îl cunoașteți"
                act_en = f"call {person} on his old number, the one you know"
        else:
            act_ro = f"sunați-vă {who_ro} la numărul vechi, pe care îl cunoașteți" if who_ro != "persoana" else \
                "sunați persoana la numărul vechi, pe care îl cunoașteți"
            act_en = f"call {who_en} on the old number, the one you know"
        return {"ro": f"{h_ro} {src_ro} se dă drept {rel_ro} și {ask_ro}. {dont_ro}: {act_ro}.",
                "en": f"{h_en} {src_en} is pretending to be {rel_en} and {ask_en}. {dont_en}: {act_en}."}

    if st == "BANK_IMPERSONATION":
        o_ro = org or "banca dumneavoastră"
        o_en = org or "your bank"
        act_ro = (f"sunați la {org}, la {phone}, sau la numărul de pe spatele cardului" if phone
                  else "sunați la numărul de pe spatele cardului")
        act_en = (f"call {org} on {phone}, or the number on the back of your card" if phone
                  else "call the number on the back of your card")
        return {"ro": f"{h_ro} {who_ro} {o_ro}, dar {why_ro}. {stop_ro} și nu dați coduri sau date; {act_ro}.",
                "en": f"{h_en} {who_en} {o_en}, but {why_en}. {stop_en} and give no codes or details; {act_en}."}

    if st == "COURIER_FEE":
        o_ro = f"firma de curierat {org}" if org else "o firmă de curierat"
        o_en = f"the courier {org}" if org else "a courier company"
        if phone:
            act_ro, act_en = f"dacă așteptați un colet, sunați la {org}, la {phone}", f"if you expect a parcel, call {org} on {phone}"
        else:
            act_ro = "dacă așteptați un colet, sunați firma de curierat la numărul de pe site-ul ei oficial"
            act_en = "if you expect a parcel, call the courier on the number from its official website"
        return {"ro": f"{h_ro} {who_ro} {o_ro}, dar {why_ro}. Nu plătiți nimic prin mesaj; {act_ro}.",
                "en": f"{h_en} {who_en} {o_en}, but {why_en}. Do not pay anything through the message; {act_en}."}

    if st == "AUTHORITY_IMPERSONATION":
        if org == "ANAF":
            a_ro, a_en = "ANAF", "ANAF"
        else:
            a_ro, a_en = _authority_name(folded)
        if phone and org == "ANAF":
            act_ro, act_en = f"dacă aveți o nelămurire, sunați la ANAF, la {phone}", f"if in doubt, call ANAF on {phone}"
        else:
            act_ro = "dacă aveți o nelămurire, mergeți direct la ghișeul instituției"
            act_en = "if in doubt, go in person to the institution's office"
        return {"ro": f"{h_ro} {who_ro} {a_ro}, dar {why_ro}. Nu dați date și nu plătiți nimic; {act_ro}.",
                "en": f"{h_en} {who_en} {a_en}, but {why_en}. Give no details and pay nothing; {act_en}."}

    if st == "TECH_SUPPORT":
        return {"ro": f"{h_ro} Cineva se dă drept suport tehnic și {_reasons(flags, k=1)[0]}. "
                      "Închideți și nu instalați nimic; dacă ați intrat deja în contul de bancă, sunați la numărul de pe spatele cardului.",
                "en": f"{h_en} Someone is pretending to be technical support and {_reasons(flags, k=1)[1]}. "
                      "Hang up and install nothing; if you already opened your bank account, call the number on the back of your card."}

    if st == "MARKETPLACE":
        if "RF_DATA_REQUEST" in flags:
            s2_ro = "Un așa-zis cumpărător vă cere datele cardului, dar ca să primiți bani nu trebuie să le dați niciodată."
            s2_en = "A so-called buyer asks for your card details, but you never need them to receive money."
        else:
            s2_ro = f"Un așa-zis cumpărător {why_ro}."
            s2_en = f"A so-called buyer {why_en}."
        return {"ro": f"{h_ro} {s2_ro} Nu apăsați pe adresa primită; vorbiți și primiți banii doar prin aplicația oficială {org or 'a site-ului de anunțuri'}.",
                "en": f"{h_en} {s2_en} Do not open the address you received; talk and get paid only inside the official {org or 'marketplace'} app."}

    if st == "ACCOUNT_TAKEOVER":
        nm = _clean_name(x.get("sender_name")) if r.get("known_contact") else None
        if nm:
            s2_ro = "Contul acestei persoane pare să fi fost preluat de altcineva, care vă cere un cod primit prin SMS."
            s2_en = "This person's account seems to have been taken over by someone who asks for a code you received by SMS."
            act_ro = (f"sunați-o pe {nm}" if _female(nm) else f"sunați-l pe {nm}") + " la numărul pe care îl știți, ca să verificați"
            act_en = f"call {nm} on the number you know to check"
            return {"ro": f"{h_ro} {s2_ro} Nu trimiteți codul; {act_ro}.", "en": f"{h_en} {s2_en} Do not send the code; {act_en}."}
        return {"ro": f"{h_ro} Cineva vă cere un cod primit prin SMS, iar cu el vă poate fura contul. Nu trimiteți codul nimănui, nici prietenilor.",
                "en": f"{h_en} Someone asks for a code you received by SMS, and with it they can steal your account. Do not send the code to anyone, not even friends."}

    if st == "INVESTMENT":
        return {"ro": f"{h_ro} Mesajul {why_ro}, dar nimeni nu poate garanta câștiguri. "
                      "Nu trimiteți bani; întrebați întâi la banca dumneavoastră, la numărul de pe spatele cardului.",
                "en": f"{h_en} The message {why_en}, but nobody can guarantee profits. "
                      "Do not send money; first ask your bank, on the number on the back of your card."}

    if st == "ROMANCE":
        return {"ro": f"{h_ro} O persoană cunoscută doar pe internet {why_ro}. Nu trimiteți bani; vorbiți întâi cu cineva drag din familie.",
                "en": f"{h_en} Someone you only know online {why_en}. Do not send money; talk to someone in your family first."}

    if st == "JOB_OFFER":
        return {"ro": f"{h_ro} Vi se promit bani ușor pentru treburi simple, iar apoi vi se cer bani sau date. "
                      "Nu plătiți nicio garanție și nu dați datele cardului; un loc de muncă adevărat nu vă cere bani.",
                "en": f"{h_en} You are promised easy money for simple tasks, and then asked for money or details. "
                      "Pay no deposit and give no card details; a real job never asks you for money."}

    if st == "PRIZE_LOTTERY":
        w_ro, w_en = _reasons(flags, skip=("RF_TOO_GOOD",), k=1)
        at_ro = f" la {org}" if org else ""
        at_en = f" from {org}" if org else ""
        act_ro = (f"dacă vreți să verificați, sunați la {org}, la {phone}" if phone else "nu ați participat la nicio tombolă")
        act_en = (f"if you want to check, call {org} on {phone}" if phone else "you did not enter any draw")
        return {"ro": f"{h_ro} Mesajul spune că ați câștigat un premiu{at_ro}, dar {w_ro}. Nu răspundeți și nu dați date; {act_ro}.",
                "en": f"{h_en} The message says you won a prize{at_en}, but {w_en}. Do not reply and give no details; {act_en}."}

    # OTHER / anything else
    return {"ro": f"{h_ro} Mesajul {why_ro}. Nu trimiteți bani, coduri sau date; sunați persoana sau firma la un număr pe care îl cunoașteți deja.",
            "en": f"{h_en} The message {why_en}. Do not send money, codes or details; call the person or company on a number you already know."}
