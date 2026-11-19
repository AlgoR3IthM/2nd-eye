"""Evaluate a (merged fp16) model on the held-out synthetic dev split: JSON validity, flag precision/recall, scam type accuracy.
Usage: python training/eval_dev.py [model_dir]   (default training/out/merged; pass hf/Qwen3-4B-Instruct-2507 for the base). No texts printed."""
import json, sys, re, torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
H = Path(__file__).resolve().parent
md = Path(sys.argv[1]) if len(sys.argv) > 1 else H / "out" / "merged"
tok = AutoTokenizer.from_pretrained(H / "hf" / "Qwen3-4B-Instruct-2507"); tok.padding_side = "left"
model = AutoModelForCausalLM.from_pretrained(md, dtype=torch.float16, device_map={"": 0}).eval()
rows = [json.loads(l) for l in open(H / "data" / "dev.jsonl", encoding="utf-8")]
prompts = [tok.apply_chat_template(r["messages"], tokenize=False, add_generation_prompt=True) for r in rows]
outs = []
B = 8
for i in range(0, len(rows), B):
    enc = tok(prompts[i:i + B], return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
    with torch.no_grad():
        g = model.generate(**enc, max_new_tokens=700, do_sample=False, pad_token_id=tok.pad_token_id)
    outs += tok.batch_decode(g[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)
valid = tp = fp = fn = type_ok = ev_ok = ev_n = 0
fp_neg = neg_n = 0
for r, o in zip(rows, outs):
    gold = json.loads(r["target"])
    try:
        pred = json.loads(o[o.find("{"): o.rfind("}") + 1]); valid += 1
    except Exception:
        fn += sum(len(p["flags"]) for p in gold["per_message"]); continue
    G = {(p["n"], f["code"]) for p in gold["per_message"] for f in p["flags"]}
    texts = {int(m.split("]")[0][1:]): m.split(": ", 1)[1] for m in r["messages"][1]["content"].split("\n") if re.match(r"\[\d+\] ", m)}
    Pp = set()
    for p in pred.get("per_message", []) if isinstance(pred, dict) else []:
        for f in p.get("flags", []):
            Pp.add((p.get("n"), f.get("code")))
            ev_n += 1; ev_ok += f.get("evidence", "") in texts.get(p.get("n"), "")
    tp += len(G & Pp); fp += len(Pp - G); fn += len(G - Pp)
    type_ok += pred.get("scam_type") == gold["scam_type"]
    if r["kind"] == "neg":
        neg_n += 1; fp_neg += bool(Pp)
n = len(rows)
res = {"model": str(md.name), "n": n, "json_valid": valid / n, "flag_precision": tp / max(1, tp + fp), "flag_recall": tp / max(1, tp + fn),
       "scam_type_acc": type_ok / n, "evidence_verbatim": ev_ok / max(1, ev_n), "neg_examples_with_any_flag": fp_neg / max(1, neg_n)}
print(json.dumps(res)); (H / "out" / f"dev_{md.name}.json").write_text(json.dumps(res, indent=1))
