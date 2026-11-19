"""Chat import: turns a pasted or exported conversation into a standard scenario. Never raises, never logs text.

parse(text)  -> {"format", "participants", "messages": [{"author", "text"}]}
to_scenario(parsed, me, channel, known_contact) -> scenario dict for fusion.analyze
Dates are never interpreted (only recognised), so dd.mm.yyyy, dd/mm/yy and mm/dd/yy all work, 24 h or 12 h.
"""
import re
import unicodedata

_INVISIBLE = dict.fromkeys(map(ord, "‎‏‪‫‬‭‮⁦⁧⁨⁩​‌‍⁠﻿"), None)

_DATE = r"\d{1,4}[./-]\d{1,2}[./-]\d{1,4}"
_TIME = r"\d{1,2}[:.]\d{2}(?:[:.]\d{2})?(?:\s?[AaPp]\.?\s?[Mm]\.?)?"

# header -> (author_and_text_remainder). The remainder is "Author: text" (or a system line without author).
_RE_WEB = re.compile(r"^\[\s*(?:%s)\s*,\s*(?:%s)\s*\]\s*(.*)$" % (_TIME, _DATE))
_RE_IOS = re.compile(r"^\[\s*(?:%s)\s*,?\s*(?:%s)\s*\]\s*(.*)$" % (_DATE, _TIME))
_RE_AND = re.compile(r"^(?:%s)\s*,?\s*(?:%s)\s+[-–—]\s+(.*)$" % (_DATE, _TIME))
_RE_TG = re.compile(r"^(.{1,60}?),\s*\[\s*(?:%s)[ ,]+(?:%s)\s*\]\s*$" % (_DATE, _TIME))
_RE_AUTH = re.compile(r"^(.{1,60}?):\s+(.*)$", re.S)
_RE_GEN = re.compile(r"^([^\W\d_][^:\n]{0,30}?):\s*(\S.*)$")

_ME_NAMES = ("eu", "tu", "me", "you")

_SYSTEM = [re.compile(p) for p in (
    r"^<?\s*(media|multimedia|imagine|image|video|audio|sticker|gif|document|fisier|file)s?\b.{0,20}(omitted|omise|omis|omisa|omisă|attached)\b",
    r"^<\s*attached\s*:",
    r"^<[^>]{0,30}(omitted|omise|omis)\s*>$",
    r"^mesaj(ul)? (a fost )?sters",
    r"^acest mesaj a fost sters",
    r"^(this message was deleted|you deleted this message|message deleted)",
    r"^(mesajele si apelurile|messages and calls) .{0,80}(criptate|encrypted)",
    r"^(apel|apelul) (vocal |video )?(pierdut|ratat|fara raspuns)",
    r"^(missed|unanswered) (voice|video) call",
    r"^(a adaugat|a parasit|a iesit|ai adaugat|ai fost adaugat|s-a alaturat)",
    r"^(security code changed|codul de securitate)",
)]


def _fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def _is_system(text: str) -> bool:
    f = _fold(text).strip()
    if not f:
        return True
    if len(f) > 200:
        return False
    return any(p.search(f) for p in _SYSTEM)


def _norm(text: str) -> str:
    text = text.translate(_INVISIBLE)
    out = []
    for ch in text:
        if ch in "\r\n\t":
            out.append(ch)
        elif unicodedata.category(ch) == "Zs":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out).replace("\r\n", "\n").replace("\r", "\n")


def _clean_name(n: str) -> str:
    n = n.strip().lstrip("~").strip()
    return n[:60]


def _plain(text: str) -> dict:
    t = (text or "").strip()
    return {"format": "plain", "participants": [],
            "messages": [{"author": None, "text": t}] if t else []}


def _split_auth(rest: str):
    m = _RE_AUTH.match(rest)
    if not m:
        return None, rest
    name = _clean_name(m.group(1))
    if not name or len(name.split()) > 6:
        return None, rest
    return name, m.group(2)


def _build(lines, fmt):
    """Run one format over the lines; returns raw list of [author, [text lines]] (author None = system/unknown)."""
    msgs = []
    cur = None
    for ln in lines:
        author = text = None
        header = False
        if fmt == "telegram":
            m = _RE_TG.match(ln)
            if m:
                header, author, text = True, _clean_name(m.group(1)), ""
        elif fmt == "generic":
            m = _RE_GEN.match(ln)
            if m and len(m.group(1).split()) <= 3:
                header, author, text = True, _clean_name(m.group(1)), m.group(2)
        else:
            rx = {"whatsapp_web": _RE_WEB, "whatsapp_ios": _RE_IOS, "whatsapp_android": _RE_AND}[fmt]
            m = rx.match(ln)
            if m:
                header = True
                author, text = _split_auth(m.group(1))
        if header:
            cur = [author, [text] if text is not None else []]
            msgs.append(cur)
        elif cur is not None:
            cur[1].append(ln)
    return msgs


def parse(text: str) -> dict:
    try:
        if not isinstance(text, str):
            return _plain("")
        norm = _norm(text)
        lines = norm.split("\n")
        counts = {
            "whatsapp_web": sum(1 for l in lines if _RE_WEB.match(l)),
            "whatsapp_ios": sum(1 for l in lines if _RE_IOS.match(l)),
            "whatsapp_android": sum(1 for l in lines if _RE_AND.match(l)),
            "telegram": sum(1 for l in lines if _RE_TG.match(l)),
        }
        fmt = max(counts, key=lambda k: counts[k])
        if counts[fmt] == 0:
            fmt = "generic"
            gen = [m.group(1) for m in (_RE_GEN.match(l) for l in lines) if m and len(m.group(1).split()) <= 3]
            names = {_clean_name(g).lower() for g in gen}
            # a lone "Atenție: ..." must stay plain text; need two voices, or a known "me" word plus content
            if len(gen) < 2 or len(names) < 2:
                return _plain(norm)
        raw = _build(lines, fmt)
        messages, participants = [], []
        for author, parts in raw:
            body = "\n".join(parts).strip()
            if author is None and fmt != "generic":
                continue   # system line (encryption notice, "X added Y", ...)
            if not body or _is_system(body):
                continue
            if author not in participants:
                participants.append(author)
            messages.append({"author": author, "text": body})
        if not messages:
            return _plain(norm) if fmt == "generic" else {"format": fmt, "participants": [], "messages": []}
        return {"format": fmt, "participants": participants, "messages": messages}
    except Exception:
        return _plain(text if isinstance(text, str) else "")


def guess_me(participants, remembered=None):
    """Helper for callers: a participant called Eu/Tu/Me/You, else the remembered name."""
    for p in participants:
        if _fold(p).strip() in _ME_NAMES:
            return p
    if remembered and remembered in participants:
        return remembered
    return None


def to_scenario(parsed: dict, me, channel: str, known_contact: bool) -> dict:
    msgs = (parsed or {}).get("messages") or []
    parts = (parsed or {}).get("participants") or []
    if me is not None and me not in parts:
        me = None
    others = [p for p in parts if p is not None and p != me]
    name = others[0] if len(others) == 1 else None
    out = []
    for i, m in enumerate(msgs, 1):
        is_me = me is not None and m.get("author") == me
        out.append({"n": i, "from": "reader" if is_me else "sender", "text": m.get("text", "")})
    return {
        "id": "CHAT",
        "channel": channel if isinstance(channel, str) and channel else "whatsapp",
        "sender": {"name": name, "address": None, "known_contact": bool(known_contact)},
        "messages": out,
    }


if __name__ == "__main__":
    import json
    ok = True

    def check(label, cond):
        global ok
        ok = ok and bool(cond)
        print(("PASS " if cond else "FAIL ") + label)

    web = ("[14:05, 19.11.2026] Ana: Buna ziua, sunt Ana\n"
           "[14:06, 19.11.2026] Eu: Buna! Cine e?\n"
           "[14:07, 19.11.2026] Ana: Mama, mi-am schimbat numarul.\n"
           "Poti sa-mi trimiti 500 lei? \U0001F64F\n"
           "[14:08, 19.11.2026] Eu: <Media omitted>\n"
           "[14:09, 19.11.2026] Eu: Acest mesaj a fost șters\n")
    p = parse(web)
    check("web format", p["format"] == "whatsapp_web")
    check("web participants", p["participants"] == ["Ana", "Eu"])
    check("web multi-line + emoji + system skipped", len(p["messages"]) == 3 and p["messages"][2]["text"].startswith("Mama") and "\n" in p["messages"][2]["text"] and "\U0001F64F" in p["messages"][2]["text"])

    android = ("19.11.2026, 14:05 - Mesajele și apelurile sunt criptate end-to-end. Nimeni din afara acestei conversații nu le poate citi.\n"
               "19.11.2026, 14:05 - Ana: Salut Ioane\n"
               "19.11.2026, 14:06 - Ioan Pop: Salut, ce faci?\n"
               "19.11.2026, 14:07 - Ana: Ma ajuti cu un transfer?\n"
               "da repede te rog\n"
               "19.11.2026, 14:08 - Ioan Pop: apel vocal pierdut\n")
    p = parse(android)
    check("android format", p["format"] == "whatsapp_android" and p["participants"] == ["Ana", "Ioan Pop"] and len(p["messages"]) == 3)
    check("android continuation", p["messages"][2]["text"] == "Ma ajuti cu un transfer?\nda repede te rog")

    android12 = "11/19/26, 2:05 PM - Ana: hello\n11/19/26, 2:06 PM - Eu: hi\n19/11/26, 2:07 pm - Ana: x"
    p = parse(android12)
    check("android 12h, NNBSP, mm/dd/yy", p["format"] == "whatsapp_android" and len(p["messages"]) == 3)

    ios = ("‎[19.11.2026, 14:05:12] Ana: ‎Salut\n"
           "[19.11.2026, 14:05:40] Tu: Buna\n"
           "[19.11.2026, 2:06:00 PM] Ana: imagine omisă\n"
           "[19.11.2026, 14:06:10] Ana: Trimite banii pe cardul asta\n")
    p = parse(ios)
    check("ios format", p["format"] == "whatsapp_ios" and p["participants"] == ["Ana", "Tu"] and len(p["messages"]) == 3)

    tg = ("Ana, [19.11.2026 14:05]\nSalut, sunt eu\nmai am o intrebare\n\n"
          "Mihai, [19.11.2026 14:06]\nBuna\n\n"
          "Ana, [19.11.2026 14:07]\nSpune-mi codul primit prin SMS\n")
    p = parse(tg)
    check("telegram", p["format"] == "telegram" and p["participants"] == ["Ana", "Mihai"] and len(p["messages"]) == 3 and p["messages"][0]["text"] == "Salut, sunt eu\nmai am o intrebare")

    gen = "Eu: Buna ziua\nBanca: Contul dvs este blocat\nvizitati linkul\nEu: Nu dau nimic\n"
    p = parse(gen)
    check("generic", p["format"] == "generic" and p["participants"] == ["Eu", "Banca"] and len(p["messages"]) == 3 and "\n" in p["messages"][1]["text"])

    grp = ("[10:00, 19.11.2026] Ana: Salut tuturor\n[10:01, 19.11.2026] Bogdan: Buna\n"
           "[10:02, 19.11.2026] ~ Cezar: Salutare\n[10:03, 19.11.2026] Ana: Ana a adaugat-o pe Dana\n"
           "[10:04, 19.11.2026] Ana added Dana\n")
    p = parse(grp)
    check("group of three", p["participants"] == ["Ana", "Bogdan", "Cezar"] and len(p["messages"]) == 4)
    sc = to_scenario(p, "Bogdan", "whatsapp", False)
    check("group scenario: sender name None, reader only Bogdan", sc["sender"]["name"] is None and [m["from"] for m in sc["messages"]] == ["sender", "reader", "sender", "sender"])

    for txt in ("Atentie: contul dvs este blocat, apasati linkul", "Doar un mesaj simplu fara structura.", "", "   "):
        p = parse(txt)
        check("plain %r" % txt[:20], p["format"] == "plain" and len(p["messages"]) == (1 if txt.strip() else 0) and (not p["messages"] or p["messages"][0]["author"] is None))
    check("non-str never raises", parse(None)["format"] == "plain")

    p = parse(web)
    sc = to_scenario(p, "Eu", "whatsapp", True)
    check("scenario numbering/direction", [(m["n"], m["from"]) for m in sc["messages"]] == [(1, "sender"), (2, "reader"), (3, "sender")] and sc["sender"]["name"] == "Ana" and sc["sender"]["known_contact"] is True)
    sc = to_scenario(p, "Ana", "sms", False)
    check("me=Ana flips direction", [m["from"] for m in sc["messages"]] == ["reader", "sender", "reader"])
    check("guess_me", guess_me(["Ana", "Eu"]) == "Eu" and guess_me(["Ana", "Dan"], "Dan") == "Dan" and guess_me(["Ana", "Dan"]) is None)
    print("SELF-TEST", "OK" if ok else "FAILED")
    raise SystemExit(0 if ok else 1)
