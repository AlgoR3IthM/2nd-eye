# Scam Shield — AlgoR3IthM — Plan & Contract

Hackathon: R Systems side challenge, EESTEC LC Bucharest. Code freeze **17:00**. Requirements live in `Cerinte/`
(brief, `official_catalog.json`, `validation_set/V01..V11.json`, `validation_expected_results.csv`, AI scoring tiers).

Product name in the GUI: **„2nd Eye” by AlgoR3IthM** (Scam Shield). Romanian first, English toggle.

## Status at 11:20 — read this first

| Part | State |
|---|---|
| `backend/rules.py`, `contacts.py`, `calibration.json`, `llm.py`, `patterns.json` | Written, never run together |
| `backend/fusion.py`, `warnings_ro.py`, `evaluate.py` | **Missing — blocks everything** |
| `backend/server.py`, `run.bat`, `README.md` | **Missing** |
| `web/index.html` | Written, tested only against a mock of the §3 contract |
| `integrations/telegram_bot.py`, `integrations/extension/*` | Written, untested against the real API |

Next tasks, in order: (1) `fusion.py` + `evaluate.py` until 11/11 without the LLM, (2) `warnings_ro.py`, (3) `server.py`,
(4) load the validation folder in the real GUI, (5) only then the model work in §2b and the extra sources in §2c.
A stale lock `.locks/backend__fusion.py.lock` is left from a stopped agent; a human may delete it.

## 0. Rules that can disqualify or zero us

1. **No message text may ever go to a cloud AI at runtime.** Detector = local only (LM Studio on this laptop's RTX 3080). Tier 0 = disqualified.
2. **The secret Test Set never touches any cloud assistant** (Claude, Copilot, ChatGPT…). It arrives after freeze anyway.
3. **Live re-run must equal the dashboard row**, or accuracy = 0. Everything is deterministic: rules, temperature 0, fixed seed.
4. Never repeat a link/number from the suspicious message as something to use; never invent numbers. Official numbers come only from `official_catalog.json`.
5. No API keys in code (`.env`, git-ignored). No message content written to disk or logs.

## 1. What scores points (100 + tier bonus)

| Criterion | Pts | Our answer |
|---|---|---|
| Test Set accuracy | 30 | Verdict 3, type 2, first alert 2 per scenario; scam marked SAFE = −3. Exact flags/score are *not* scored, only what they imply. |
| Warning quality | 25 | Deterministic Romanian templates (dumneavoastră, ≤3 short sentences, one official-channel action). No LLM-written warnings. |
| Ease of use | 20 | One big button, paste → coloured result with icon + words, phone-readable, ≥18 px. |
| Pitch & teamwork | 15 | 3 min, more than one speaker, honest limits. |
| Innovation | 10 | Trust Circle gate, forward-to-bot, WhatsApp Web guard, read aloud, call a trusted person. |
| **Tier 6 bonus** | +10% | Ensemble: local LLM + rules + link/number checks + calibration. |

## 2. Architecture — one local API, many front doors

```
 Web GUI/PWA ─┐
 Telegram bot ─┤
 WhatsApp Web ─┼─►  FastAPI (localhost:8000)  ─►  fusion.analyze(scenario)
 extension     │                                    ├─ Signal A  rules.py     Romanian intent rules (diacritic-insensitive)
 Email (.eml) ─┘                                    ├─ Signal B  contacts.py  links / sender / phone vs official catalog, lookalikes
                                                    ├─ Signal C  llm.py       local LLM, few-shot + retrieved patterns, JSON-schema output
                                                    └─ calibration.json       per-flag acceptance thresholds
                                                    → official formula → verdict, type, first alert → warnings_ro.py
```

Thread logic: score **cumulatively after every message** (reader messages count for numbering, only sender messages produce flags).
`first_alert` = first `n` where cumulative score ≥ 25. Single non-SAFE message → `first_alert = 1`. SAFE → `null`.
Early false flags are worse than late ones (early = 0 pts, one late = 1 pt): message 1 of V04 must score exactly 20.

### Lessons from the answer key (must hold)
- A genuine organisation message (official sender name, only official links, nothing requested) → **zero flags**, including no `RF_IMPERSONATION` (V03, V05).
- A message that *delivers* a code and says not to share it is not `RF_CODE_REQUEST` (V03).
- `RF_SUSPICIOUS_CONTACT` fires on unofficial links / e-mail domains, **not** on a plain unknown mobile number (V07, V09, V11).
- `known_contact: true` is not safety (V10 = SCAM, account takeover).
- A refund is not automatically `RF_TOO_GOOD` (V06), but "good news, more money" as a hook is (V11).

### Trust Circle (the "scan only strangers" idea, made safe)
- **Live integrations** (WhatsApp Web, Telegram, e-mail): messages from saved contacts are *not* analysed — privacy by data minimisation. Only a tiny on-device **tripwire** runs on them (code / remote access / card data / money request). If it trips, full analysis runs. This is what catches V10.
- **File / paste / dashboard mode: always full analysis** (`trust_gate=false`). Skipping known contacts there would lose V10-style cases (−8 pts each).

## 2b. The model: small local LLM, fine-tuned only if time allows (team decision, confirmed with mentors)

- Signal C is a **4B–8B instruct model running locally** in LM Studio. Rules and link checks decide most of the score; the model only
  adds flags with an exact evidence quote, so a small model is enough.
- Tier check: an off-the-shelf local model + rules + link/number checks + calibration is already **tier 6 (+10%)**.
  Fine-tuning does not raise the bonus; do it for accuracy and for the pitch, not for the tier.
- Order: first ship the pipeline with the base model. Fine-tune as an upgrade behind `SCAMSHIELD_MODEL`, base model kept as fallback.
- Fine-tune recipe (QLoRA, fits the 16 GB RTX 3080):
  - Task = exactly what `llm.py` asks: thread in, JSON out (per-message flags with evidence, scam type, claimed organisation, person name).
  - Data: 600–1500 synthetic Romanian threads written by the team or generated by the local model. At least 40% genuine messages that
    look dangerous. Include diacritic-free text and slow-burn threads. **Nothing from the Validation or Test Set in the training data.**
  - 4-bit base, LoRA rank 16, 2–3 epochs; export to GGUF Q4_K_M; load in LM Studio.
  - The Validation Set and the self-test cases are the held-out check.
- **Go/no-go at 14:30:** the fine-tuned model ships only if it beats the base model on validation + self-test and still answers in
  under 10 s per scenario. Otherwise ship the base model.
- Main risk is setup time on Windows (CUDA PyTorch, the QLoRA toolchain, GGUF conversion), not training time. One person owns it; nobody else waits on it.

## 2c. Sources: one detector, many readers

| Platform | Route | Sources | Today |
|---|---|---|---|
| Windows | Chrome extension in the person's normal Chrome (not a hidden/automated browser: Google blocks sign-in there) with one reader per site | WhatsApp Web, Gmail | Build |
| Windows | Same extension | Messenger, Instagram | Demo page only: Meta forbids scraping and pages break often — say so in the pitch |
| Android | **Notification listener** app (WAMR style): one permission gives sender + text from WhatsApp, Messenger, Instagram, SMS, Gmail; posts to the laptop API over Wi-Fi | all | Only if someone knows Kotlin; otherwise roadmap slide |
| Any phone | Phone-readable web GUI + Telegram forwarding bot | pasted / forwarded text | Build |

**Decision 11:35 — the main route is the watcher** (`integrations/watcher/`): a Python launcher (Playwright) spins up a Chromium
instance with its own saved profile, opens WhatsApp Web, Messenger, Instagram, Telegram Web and Gmail in tabs, and injects one reader
script per service. Readers hand the open conversation to Python through an exposed binding (page CSP blocks direct calls to
localhost), Python calls the local API. A relative logs in once in a visible window (`--login`); after that the watcher runs as a
**hidden background service** (headless). Hidden means nobody opens chats, so it reads the conversation list (unread rows: sender +
preview) without clicking; opening a chat would mark it as read on her phone, so that is opt-in for strangers only. Results go to a
local status page (`127.0.0.1:8010`); `--show` gives the visible in-page banner for the demo. `--lite` = one tab at a time, no
images, rules-only detection, for low-end PCs. No Android notification listener for now; alerting the grandparent outside the
browser is a later topic. The extension in `integrations/extension/` stays as a second door for a normal Chrome.

**Decisions 12:05:** the Telegram forwarding bot is dropped (`integrations/telegram_bot.py` is unused; Telegram Web stays a watcher
service). Windows autostart is installed with administrator rights. Folder merge with the Live Share workspace happens later.
(Scrapped 16:10: Android is Raul's app; the old `android-webwatcher/` is only in git history.) It was planned as an Android app: WebViews with a desktop user agent
load the same five services and inject the **same reader files** from `integrations/watcher/readers/`; a JavaScript bridge replaces
Playwright's binding; a foreground service keeps it running; detection calls the laptop API over Wi-Fi. The teammate's
`scam-shield-android` notification app is separate and merges later.

Chrome on Android has no extensions and kills background tabs, so the extension route is Windows-only.
Every reader produces the standard scenario JSON and applies the Trust Circle: a saved name → tripwire only; a bare number or unknown address → full scan.
Extension layout: `integrations/extension/content.js` holds shared logic; one reader file per site (`reader_whatsapp.js`, `reader_gmail.js`, …), one owner each.

## 3. API contract (do not change without updating this section)

`POST /api/analyze` — body = scenario JSON in the standard format, optional query `?trust_gate=true`.
`POST /api/analyze-text` — `{ "text": str, "channel": "sms", "known_contact": false }` → wrapped as a 1-message scenario.
`GET /api/health` → `{ "ok": true, "llm": bool, "model": str|null }`
`GET /api/catalog` → official catalog. `GET /` → `web/index.html`.

Response of both analyze endpoints:
```json
{
  "id": "V04", "channel": "whatsapp", "known_contact": false,
  "verdict": "SCAM", "scam_type": "FAMILY_EMERGENCY", "risk_score": 80,
  "first_alert": 5,
  "red_flags": ["RF_NEW_NUMBER", "RF_PAYMENT_REQUEST", "RF_URGENCY", "RF_SECRECY"],
  "label": { "ro": "Pare o țeapă! Nu răspundeți", "en": "Looks like a scam! Do not reply" },
  "warning": { "ro": "…max 3 propoziții…", "en": "…" },
  "per_message": [
    { "n": 1, "from": "sender", "text": "…", "new_flags": ["RF_NEW_NUMBER"],
      "cumulative_score": 20, "verdict_so_far": "SAFE",
      "highlights": [ { "start": 0, "end": 9, "flag": "RF_NEW_NUMBER" } ] }
  ],
  "signals": { "rules": ["RF_…"], "contacts": ["RF_…"], "llm": ["RF_…"], "llm_used": true, "skipped_by_trust_gate": false }
}
```
`red_flags` ordered by first appearance. `first_alert` is `null` for SAFE. `text` is echoed only in the response, never stored.

### Python interfaces
```python
# backend/fusion.py
def analyze(scenario: dict, use_llm: bool = True, trust_gate: bool = False) -> dict   # returns the response above; never raises
# backend/llm.py
def available() -> bool
def model_name() -> str | None
def analyze(scenario: dict) -> dict | None
#   -> {"per_message": [{"n": 1, "flags": [{"code": "RF_…", "evidence": "exact quote from that message"}]}],
#       "scam_type": "…", "claimed_org": str|None, "person_name": str|None}   or None if LLM down / invalid output
# backend/rules.py
def detect(text: str, ctx: dict) -> list[dict]      # [{"code","start","end"}], ctx = {channel, known_contact, sender, n, prior_flags}
# backend/contacts.py
def check(text: str, sender: dict, channel: str) -> dict   # {"flags":[…], "official_org": str|None, "unofficial_links":[…], "highlights":[…]}
# backend/warnings_ro.py
def build(result: dict, llm_extra: dict | None) -> dict     # {"ro": str, "en": str}
```
Fusion rule: a flag is accepted if a rule or the contact checker finds it; an LLM-only flag is accepted only if its `evidence`
quote really occurs in that message **and** it passes the per-flag threshold in `calibration.json`. The genuine-message guard overrides all.
The app must work fully with the LLM switched off (`use_llm=False`) — that is the fallback if LM Studio dies on stage.

## 4. Files and owners (one owner per file)

| File | Owner | Purpose |
|---|---|---|
| `backend/rules.py`, `backend/contacts.py`, `backend/fusion.py`, `backend/warnings_ro.py`, `backend/calibration.json`, `backend/evaluate.py` | DETECTOR | Signals A+B, ensemble, scoring, warnings, validation check |
| `backend/llm.py`, `backend/patterns.json`, `backend/server.py`, `run.bat`, `README.md` | SERVER | Local LLM signal, API, launcher |
| `web/index.html` | GUI | Whole GUI + dashboard in one self-contained file (no CDN) |
| `integrations/telegram_bot.py`, `integrations/extension/*`, `integrations/README.md` | INTEGRATIONS | Forwarding bot, WhatsApp Web guard |
| `integrations/watcher/*` (`watcher.py`, `readers/*.js`, `demo/*`, `README.md`) | WATCHER | Chromium instance + one reader per service |
| `integrations/notifier/*` (`notifier.py`, `start_all.ps1`, `install_autostart.ps1`, `uninstall_autostart.ps1`) | NOTIFIER | Windows toast (low-battery style) for each SCAM/SUSPICIOUS alert from `127.0.0.1:8010/alerts.json`; autostart at sign-in |
| Android notification app | teammate (human) | Same alerts, on the phone |
| `PLAN.md`, `PITCH.md` | humans / lead | |

`python backend/evaluate.py` must print 11/11 on verdict, type, first alert (with and without `--no-llm`).

## 5. GUI (web/index.html)

- Header: shield logo + **AlgoR3IthM**; RO/EN toggle. Two tabs: **Verifică un mesaj** and **Tablou de rezultate**.
- Check tab: big text box, "Deschide fișier", one huge button **„Verifică mesajul”**. Result card: colour + icon + words
  (🟢 ✔ „Pare în regulă”, 🟠 ⚠ „Atenție, verificați înainte să răspundeți”, 🔴 ✖ „Pare o țeapă! Nu răspundeți”), the warning in large type,
  "Ce vrea de la dumneavoastră?" icon chips (bani / date / cod / acces), buttons **🔊 Citește cu voce tare** and **📞 Sună pe cineva de încredere**.
- Thread view: chat bubbles, reader replies grey, first-alert message outlined + labelled, dangerous words highlighted, risk bar growing per message.
- Dashboard: load a folder or many files in one action; summary (total / SCAM / SUSPICIOUS / SAFE); table ID · Verdict · Type · Score · First alert · Red flags,
  sorted by ID, fits 17 rows on one screen, readable from metres away; row click → detail; CSV export; optional "compare with expected CSV".
- Accessibility: ≥18 px, high contrast, colour never the only signal, works at 360 px width.

## 6. Timeline

| By | Milestone |
|---|---|
| 12:30 | `evaluate.py` 11/11; server answers `/api/analyze`; GUI shell renders a result |
| 13:30 | Dashboard loads the validation folder and matches the CSV row by row |
| 15:00 | Bot + extension demoable; team writes 15+ own hard cases (genuine-but-scary, slow-burn threads) and re-tunes |
| 16:00 | Warnings read to a real grandparent/parent by phone; fix wording |
| 16:30 | Pitch rehearsed, freeze rehearsal: copy folder → load → dashboard in < 3 min |
| 17:00 | Freeze |

## 7. Stretch (only after 11/11 and a working dashboard)

1. **Paznicul de apel**: live call on speaker → local Whisper → re-score every sentence, warning escalates.
2. Signal D: small multilingual embedding classifier fine-tuned on synthetic Romanian scams (stronger tier-6 story).
3. `.eml` drag-and-drop, PWA share target on Android.

## 8. Pitch skeleton (3 min, 2+ speakers)

Problem (a 72-year-old and "mami, număr nou") → live demo: paste, one button, read aloud → thread demo with the alert at the right message →
how it decides (4 signals, nothing leaves the laptop, strangers only + tripwire) → honest limits (Romanian only, fictional catalog, no voice calls yet) → dashboard.
