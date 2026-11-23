# MERGE.md — merging Raul's work into 2nd Eye

Raul's pieces: (1) an Android app with an earthquake-alert style full-screen warning (`scam-shield-android`, **not in this repo**),
(2) a detection engine (a Python module `engine` with `analyze_scenario(scenario)`, **not in this repo**: only `Nou Raul/stress_test.py`
imports it — to check where it lives), (3) training data `Nou Raul/train_data.jsonl` and a 100-case benchmark `Nou Raul/stress_test.py`.

This file describes only what exists in our code today. Anything marked **to check** was not confirmed in the code.
Rules that still apply after the merge (PLAN.md §0): no message text to any cloud AI, no message text logged or written to disk,
warnings from fixed Romanian templates, deterministic results.

---

## 1. Our API contract (`backend/server.py`, port 8000)

Start: `run.bat`, or `.venv\Scripts\python.exe -m uvicorn backend.server:app --host 0.0.0.0 --port 8000 --no-access-log`.
CORS allows any origin. One analysis runs at a time (a lock around the model). All bodies are UTF-8 JSON.

Query options on all three analyze endpoints: `use_llm` (default `true`; `false` = rules + link/number checks only) and
`trust_gate` (default `false`; `true` = a known contact is only checked by the tripwire).

| Method and path | Request | Response |
|---|---|---|
| `POST /api/analyze` | scenario JSON (section 2). A non-object body is treated as an empty scenario `{"id":"INVALID","channel":"unknown","messages":[]}`. | result object (below) |
| `POST /api/analyze-text` | `{"text": str, "channel": str = "sms", "known_contact": bool = false}` | result object; wrapped as a 1-message scenario with `id: "TEXT"`, sender name and address `null` |
| `POST /api/parse-chat` | `{"text": str}` (pasted or exported chat, truncated to 400,000 characters) | `{"format", "participants": [str], "count": int, "messages": [{"author": str or null, "text": str}]}` |
| `POST /api/analyze-chat` | `{"text": str, "me": str or null, "channel": str = "whatsapp", "known_contact": bool = false}` | result object; `id: "CHAT"`; messages by `me` become `from: "reader"`, all others `from: "sender"`; sender name = the other participant if there is exactly one |
| `GET /api/health` | none | `{"ok": true, "llm": bool, "model": str or null}`; `llm` is true only if the model really answers |
| `GET /api/catalog` | none | `Cerinte/official_catalog.json`, or 404 `{"error": "catalog not found"}` |
| `DELETE /api/memo` | none | `{"cleared": int}` (empties the in-memory result memo) |
| `GET /` | none | `web/index.html` (also served under `/web/` and `/static/`) |

Errors from the analyze endpoints: HTTP 500 `{"error": "analysis failed: <ExceptionTypeName>"}` (never message content).

Chat formats recognised by `backend/chatparse.py` (`format` field): `whatsapp_web`, `whatsapp_ios`, `whatsapp_android`, `telegram`,
`generic` (`Name: text` lines), `plain` (no structure: one message, author `null`). Dates are recognised, never interpreted.

**Result object** (`fusion.analyze`, same for every analyze endpoint):
```json
{
  "id": "…", "channel": "whatsapp", "known_contact": false,
  "verdict": "SAFE | SUSPICIOUS | SCAM",
  "scam_type": "one of the catalog scam types, NONE for SAFE",
  "risk_score": 0,
  "first_alert": 1,
  "red_flags": ["RF_…"],
  "label":   {"ro": "…", "en": "…"},
  "warning": {"ro": "…", "en": "…"},
  "per_message": [{"n": 1, "from": "sender", "text": "…", "new_flags": ["RF_…"],
                   "cumulative_score": 20, "verdict_so_far": "SAFE",
                   "highlights": [{"start": 0, "end": 9, "flag": "RF_…"}]}],
  "signals": {"rules": ["RF_…"], "contacts": ["RF_…"], "llm": ["RF_…"], "llm_used": true,
              "llm_status": "ok | off | unavailable | invalid_output | no_sender_text", "skipped_by_trust_gate": false}
}
```
`first_alert` is `null` for SAFE. `red_flags` are in order of first appearance. Exact per_message keys: see PLAN.md §3 (to check against
a live response if your client depends on a key not listed above). Labels: SAFE "Pare în regulă", SUSPICIOUS "Atenție, verificați
înainte să răspundeți", SCAM "Pare o țeapă! Nu răspundeți".

Scoring (`backend/fusion.py`, points and bands loaded from the official catalog): CODE_REQUEST 35, REMOTE_ACCESS 35, DATA_REQUEST 30,
PAYMENT_REQUEST 25, SUSPICIOUS_CONTACT 25, NEW_NUMBER 20, SECRECY 20, TOO_GOOD 20, IMPERSONATION 15, URGENCY 15, THREAT 15,
EMOTIONAL_PRESSURE 10, CHANNEL_SWITCH 10. SAFE 0–24, SUSPICIOUS 25–49, SCAM 50–100. Tripwire flags for known contacts:
CODE_REQUEST, REMOTE_ACCESS, DATA_REQUEST, PAYMENT_REQUEST.

Repeatability: the server memoises up to 256 results in RAM (key = SHA-256 of the canonical scenario + model id + options). Results
produced while the model failed are not memoised. `SCAMSHIELD_LLM_URL` must be localhost (enforced in `backend/llm.py`).

## 2. Scenario JSON (input to `/api/analyze`)

Same shape as the official validation files:
```json
{
  "id": "V04",
  "channel": "sms | whatsapp | email | chat | call_transcript | …",
  "sender": {"name": "str or null", "address": "str or null", "known_contact": false},
  "messages": [
    {"n": 1, "from": "sender", "text": "…"},
    {"n": 2, "from": "reader", "text": "…"}
  ]
}
```
Only `from: "sender"` messages produce flags; `reader` messages still count for numbering and `first_alert`.
Raul's `stress_test.py` cases use this same shape plus `exp_verdict`, `exp_type`, `exp_alert` (extra keys; to check that fusion ignores
them in every path — `evaluate.py --raul` already passes such cases straight to `fusion.analyze`).

## 3. Android broadcast contract (`android-webwatcher/`)

Our app (package `com.algor3ithm.scutulbunicii.web`) sends every SCAM or SUSPICIOUS result through one class,
`app/src/main/kotlin/com/algor3ithm/scutulbunicii/web/AlertDispatcher.kt`, in three ways. No message text in any of them.

1. **Broadcast**, action `com.algor3ithm.scamshield.ALERT`, no target package (a separate APK must register its receiver at runtime;
   manifest receivers do not get implicit broadcasts on Android 8+). Extras:

   | extra | type | meaning |
   |---|---|---|
   | `service` | String | `whatsapp`, `messenger`, `instagram`, `telegram`, `gmail` |
   | `sender` | String | display name or address |
   | `verdict` | String | `SCAM` or `SUSPICIOUS` |
   | `label_ro` | String | official Romanian label from the API |
   | `warning_ro` | String | the API's `warning.ro` |
   | `risk_score` | Int | 0–100 |
   | `alert_id` | String | stable per conversation state |

   Receiver example (from our README): `registerReceiver(receiver, IntentFilter("com.algor3ithm.scamshield.ALERT"), Context.RECEIVER_EXPORTED)`.
   Any app on the phone can receive this broadcast. If both apps become one APK, prefer option 2.
2. **Same APK**: `AlertDispatcher.listener = AlertListener { alert -> … }`; `Alert(service, sender, verdict, labelRo, warningRo, riskScore, alertId)`.
3. **Fallback notification** behind `AlertDispatcher.FALLBACK_NOTIFICATION = true`. Set it to `false` (or delete `fallback()`) once
   Raul's full-screen alert receives the broadcast or the listener.

Status: the APK compiles; nothing has run on a device or emulator. Raul's app: package name, how it receives alerts today, and whether it
also calls our API directly — **to check**.

## 4. Desktop alerts feed (`integrations/watcher/watcher.py`)

`GET http://127.0.0.1:8010/alerts.json` (listens on 127.0.0.1 only; port set by `--status-port`):
```json
{"alerts": [{"id": "…", "time": "2026-11-19T15:05:00", "service": "whatsapp", "sender": "…",
             "verdict": "SCAM", "risk_score": 80, "label_ro": "…", "warning_ro": "…"}]}
```
Newest first, at most 50, in memory only, SAFE results included. `time` is ISO local time. `id` is a hash of service + sender + verdict +
conversation state. Our consumer is `integrations/notifier/notifier.py` (polls every 3 s, alerts once per new SUSPICIOUS/SCAM id).
The same field names (`label_ro`, `warning_ro`, `risk_score`) are used in the Android broadcast, so one alert UI can serve both.

## 5. Training data, side by side

| | Raul: `Nou Raul/train_data.jsonl` | Ours: `training/data/train.jsonl`, `dev.jsonl` |
|---|---|---|
| Size | 600 rows, 289 distinct inputs (duplicates) | 1,170 train + 130 dev (`training/data/stats.json`) |
| Row format | Alpaca: `{"instruction", "input", "output"}` | Chat: `{"messages": [system, user], "target", "kind", "scam_type", "style"}` |
| Input | one fixed instruction; `input` = header `Channel: <ch> \| Sender: <name> (address: <addr>, known: True/False)` then lines `[n] (sender\|reader): text` | `messages[0]` = `llm.SYSTEM_PROMPT`, `messages[1]` = `llm._build_user_prompt(...)`: byte-identical to the live prompt |
| Output | JSON string `{"red_flags": [flat list], "scam_type", "warning_ro", "official_suggestion"}` | JSON string `{"per_message": [{"n", "flags": [{"code", "evidence"}]}], "scam_type", "claimed_org", "person_name"}` |
| Flags | per thread, no position | per message, with an exact evidence quote |
| Warning | written by the model (`warning_ro`) | not learned; warnings come from `backend/warnings_ro.py` templates |
| Generated by | to check | `training/gen_data.py` (labels correct by construction, 41% genuine hard negatives, ~28% of scams ROMANCE) |

**Converter** `training/convert_raul.py` (read-only on Raul's file): parses the header and message lines, dedupes by input, places each
flag on a message with `rules.detect()` (plus a URL/e-mail check for `RF_SUSPICIOUS_CONTACT`), drops flags it cannot place,
drops examples with fewer than half their flags placed, sets `claimed_org`/`person_name` to `null`, maps unknown scam types to `OTHER`,
and builds the prompt with our `llm.py`. It drops `warning_ro` and `official_suggestion`. Last run (training/README.md): 289 inputs,
412 of 531 flags placed (78%), 0 dropped; output `training/data/raul_train.jsonl` (261) and `raul_dev.jsonl` (28), **not merged** into
`train.jsonl` yet. Some converted examples under-label (unplaced flags removed).

**Recommendation: converge on one target format, ours.** Reasons: it is exactly what the live detector asks the model for, so a
fine-tune can ship without code changes; per-message evidence is what lets fusion accept or reject a model flag; and the jury rules
want deterministic, template-based warnings, which a model-written `warning_ro` breaks. Raul's generator should emit scenario JSON
(section 2) plus per-message flags with evidence; then one script builds the chat rows with `llm.py`. Keep Raul's `warning_ro` texts as a
review source for `warnings_ro.py` wording, not as a training target. Regenerate both sets whenever `llm.py` or `patterns.json` changes
(`training/data/source_hashes.txt`). No fine-tuned model exists yet (training/README.md: run did not finish; ship the base model).

## 6. Raul's engine: benchmark or plug in

**Benchmark (exists):** `python backend\evaluate.py --raul` (add `--no-llm` for rules-only). It loads `Nou Raul/stress_test.py`
read-only, installs an in-memory module named `engine` whose `analyze_scenario` calls our `fusion.analyze`, runs his 100 seeded cases
(40 SAFE + 60 SCAM/SUSPICIOUS, seed 9991) and prints verdict / type / first-alert counts, scam→SAFE and SAFE→alarm counts, and the
mismatch patterns (ids, labels and flag codes only).

**Run his engine on the same cases:** put his `engine.py` next to `stress_test.py` and run `python "Nou Raul\stress_test.py"`
(it does `from engine import analyze_scenario`). His engine must return at least `verdict`, `scam_type`, `first_alert`. To compare on
our validation, self-test and red-team sets, `evaluate.py` needs a small switch that calls his engine instead of fusion — **does not
exist yet** (owner of `backend/evaluate.py`).

**Plug in as another signal (does not exist yet):** fusion has three signals (rules, contacts, LLM) and no hook for a fourth. A Signal D
must follow the fusion rule (PLAN.md §3): a flag counts only if it comes with a per-message position or evidence quote that really
occurs in that message and passes a per-flag threshold in `calibration.json`; the genuine-message guard overrides it. Requirements to
check in his engine before plugging in: local only (no cloud call), deterministic, no logging of text, returns per-message flags (not
only a thread-level list), runtime well under 10 s per scenario. Change owner: DETECTOR (`backend/fusion.py`, `calibration.json`).
Ship it only if `evaluate.py` stays 11/11 with and without `--no-llm` and the red team and `--raul` numbers do not get worse.

## 7. Merge checklist

| # | Task | Owner |
|---|---|---|
| 1 | Find and add Raul's `engine` module and Android project to the repo (separate folders; no edits to ours) | |
| 2 | Raul's Android app: register a runtime receiver for `com.algor3ithm.scamshield.ALERT` and show the full-screen alert from `label_ro`, `warning_ro`, `verdict`, `sender`, `service` | |
| 3 | Test the broadcast on one real phone with both APKs installed (our app has never run on a device) | |
| 4 | Decide one APK or two; if one, switch to `AlertDispatcher.listener` and set `FALLBACK_NOTIFICATION = false` | |
| 5 | If Raul's app also reads notifications and calls our API: confirm it sends the section 2 scenario JSON and uses `?trust_gate=true` for saved contacts (to check) | |
| 6 | Optional: desktop — point a second alert UI at `127.0.0.1:8010/alerts.json` (same field names) | |
| 7 | Run `python backend\evaluate.py --raul` and `--raul --no-llm`; record numbers | |
| 8 | Run Raul's engine on his own stress test; add an `evaluate.py` switch to compare engines on validation / self-test / red team | |
| 9 | Check his engine: local only, deterministic, no text logging, per-message flags | |
| 10 | Agree on our training target format; update Raul's generator to emit scenario JSON + per-message evidence | |
| 11 | Concatenate `raul_train.jsonl` into training only after reviewing under-labelled examples; keep validation and Test Set out of all training data | |
| 12 | Review Raul's `warning_ro` texts as wording ideas for `backend/warnings_ro.py` (templates stay deterministic) | |
| 13 | Update PLAN.md §4 owner table with the new files | |
