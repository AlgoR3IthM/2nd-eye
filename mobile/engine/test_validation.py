import json
import csv
from pathlib import Path
from engine import analyze_scenario

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CERINTE_DIR = BASE_DIR / "Cerinte"

# Caută automat validation_expected_results.csv și folderul validation_set oriunde în Cerinte
EXPECTED_CSV = next(CERINTE_DIR.rglob("validation_expected_results.csv"))
VAL_DIR = next(CERINTE_DIR.rglob("validation_set"))

with open(EXPECTED_CSV, "r", encoding="utf-8") as f:
    expected = {row["id"]: row for row in csv.DictReader(f)}

perfect = 0
for file_path in sorted(VAL_DIR.glob("V*.json")):
    with open(file_path, "r", encoding="utf-8") as f:
        scenario = json.load(f)
    res = analyze_scenario(scenario)
    exp = expected.get(res["id"], {})

    exp_alert = exp.get("first_alert", "").strip()
    got_alert = str(res["first_alert"]) if res["first_alert"] is not None else ""

    ok = (
        res["verdict"] == exp.get("verdict")
        and res["scam_type"] == exp.get("scam_type")
        and got_alert == exp_alert
    )
    if ok:
        perfect += 1
    status = "✅" if ok else "❌"
    print(
        f"{status} {res['id']} | Got: {res['verdict']:10s} | {res['scam_type']:23s} | score={res['risk_score']:3d} | alert={got_alert or '-':2s} | flags={res['red_flags']}\n"
        f"        Exp: {exp.get('verdict', ''):10s} | {exp.get('scam_type', ''):23s} | score={exp.get('risk_score', ''):3s} | alert={exp_alert or '-':2s}"
    )

print(f"\nScor total Validation Set: {perfect}/{len(expected)}")