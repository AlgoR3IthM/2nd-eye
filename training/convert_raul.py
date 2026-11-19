"""Convert 'Nou Raul/train_data.jsonl' (flat flags) to our per-message-evidence format. Read-only on the source.
Flags are placed with backend/rules.detect() (+ a URL/e-mail check for RF_SUSPICIOUS_CONTACT); unplaceable flags are dropped,
examples with fewer than half of their flags placed are dropped. Writes data/raul_train.jsonl and data/raul_dev.jsonl (+counts)."""
import json, re, sys, random
from pathlib import Path
H = Path(__file__).resolve().parent
sys.path.insert(0, str(H.parent / "backend")); sys.path.insert(0, str(H))
import llm, rules  # read-only imports
SRC = H.parent / "Nou Raul" / "train_data.jsonl"
URL = re.compile(r"(?:https?://)?(?:[\w-]+\.)+[a-z]{2,}(?:/\S*)?|[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)
OFFICIAL = ("bancadunarea.ro", "curierexpres.ro", "piatamea.ro", "megashop.ro", "anaf.ro")
head = re.compile(r"Channel: (\S+) \| Sender: (.*?) \(address: (.*?), known: (True|False)\)")
line = re.compile(r"^\[(\d+)\] \((sender|reader)\): (.*)$")
rows = {}
for l in open(SRC, encoding="utf-8"):
    r = json.loads(l); rows.setdefault(r["input"], r)
out, stats = [], dict(distinct=len(rows), kept=0, dropped_parse=0, dropped_flags=0, flags_total=0, flags_placed=0)
for inp, r in rows.items():
    lines = inp.split("\n"); m = head.match(lines[0])
    if not m:
        stats["dropped_parse"] += 1; continue
    ch, nm, addr, known = m.group(1), m.group(2), m.group(3), m.group(4) == "True"
    msgs = []
    for x in lines[1:]:
        mm = line.match(x)
        if mm: msgs.append({"n": int(mm.group(1)), "from": mm.group(2), "text": mm.group(3)})
        elif msgs and x.strip(): msgs[-1]["text"] += "\n" + x
    try: gold = json.loads(r["output"])
    except Exception: stats["dropped_parse"] += 1; continue
    want = [f for f in gold["red_flags"] if f in llm.FLAGS]
    placed, per = set(), []
    ctx = {"channel": ch, "known_contact": known, "sender": {"name": nm, "address": addr}}
    for mg in msgs:
        if mg["from"] != "sender": continue
        fl = []
        t = mg["text"]
        found = {}
        for h in rules.detect(t, ctx):
            found.setdefault(h["code"], (h["start"], h["end"]))
        if "RF_SUSPICIOUS_CONTACT" in want:
            for u in URL.finditer(t):
                if not any(o in u.group(0).lower() for o in OFFICIAL):
                    found.setdefault("RF_SUSPICIOUS_CONTACT", (u.start(), u.end()))
        for code in want:
            if code in found and code not in placed:
                s, e = found[code]; ev = t[s:e].strip()[:80].strip()
                if len(ev) >= 5 and ev in t:
                    placed.add(code); fl.append({"code": code, "evidence": ev})
        per.append({"n": mg["n"], "flags": fl})
    stats["flags_total"] += len(want); stats["flags_placed"] += len(placed)
    if want and len(placed) * 2 < len(want):
        stats["dropped_flags"] += 1; continue
    sc = gold["scam_type"] if gold["scam_type"] in llm.SCAM_TYPES else "OTHER"
    scen = {"id": "R", "channel": ch, "sender": {"name": nm, "address": addr, "known_contact": known}, "messages": msgs}
    cm = llm._clean_messages(scen)
    tgt = {"per_message": per, "scam_type": sc, "claimed_org": None, "person_name": None}
    out.append({"messages": [{"role": "system", "content": llm.SYSTEM_PROMPT}, {"role": "user", "content": llm._build_user_prompt(scen, cm)}],
                "target": json.dumps(tgt, ensure_ascii=False, separators=(",", ":")), "kind": "raul", "scam_type": sc, "style": []})
    stats["kept"] += 1
random.seed(1); random.shuffle(out)
k = max(1, len(out) // 10)
for name, part in (("raul_dev", out[:k]), ("raul_train", out[k:])):
    with open(H / "data" / f"{name}.jsonl", "w", encoding="utf-8") as f:
        for x in part: f.write(json.dumps(x, ensure_ascii=False) + "\n")
stats["dev"] = k; stats["train"] = len(out) - k
print(json.dumps(stats))
