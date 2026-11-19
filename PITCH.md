# 2nd Eye by AlgoR3IthM — Pitch, demo and jury answers

Slot: 8 minutes = **3 min pitch + demo**, then **5 min dashboard review and live checks**.
Scoring we aim at: Test Set accuracy 30 · warning quality 25 · ease of use 20 · pitch and teamwork 15 · innovation 10 · approach tier 6 (+10%).
Speakers: **A = ________**, **B = ________**, **C = ________** (fill in names). Pitch in English; the warnings on screen are Romanian.

---

## 1. Three-minute script

### 0:00–0:30 · Speaker A · The problem
> My grandmother is seventy-two.
> Last year she got a WhatsApp message from a number she did not know.
> "Mami, ăsta e numărul nou." Mum, this is my new number.
> Two messages later: "I'm in trouble, send me money, don't tell Dad."
> She almost paid.
> She is not careless. The message was just good.
> We built **2nd Eye**: a second pair of eyes that reads with her, on her own laptop, and warns her in plain Romanian.

### 0:30–1:10 · Speaker B · One button
*(Tab "Verifică un mesaj". Paste the prepared SMS. Press "Verifică mesajul".)*
> This is everything she sees. One box. One big button.
> She pastes the message and presses it.
> Red. An icon. Words: "Pare o țeapă! Nu răspundeți."
> Below, a short warning. Formal Romanian, at most three sentences, one safe action through the official channel.
> We never repeat the link or the number from the message.
*(Press "Citește cu voce tare".)*
> And if her eyes are tired, she presses this, and it reads the warning aloud.
*(Point at "Sună pe cineva de încredere".)*
> One more button calls her grandson.

### 1:10–1:50 · Speaker C · The slow romance
*(Tab "Importă o conversație". Paste the prepared romance thread. Under "Care dintre aceștia sunteți dumneavoastră?" pick our side. Press "Verifică conversația".)*
> Not every scam is one message. Romance scams take weeks.
> She can paste or export a whole WhatsApp chat here.
> We score it message by message, like the official formula.
> See the risk bar grow. The alert lands on the exact message where the money ask appears, not earlier.
*(Scroll to the card "Semnele unei povești de dragoste false".)*
> And this card explains why, in her words: met only online, love very fast, never on video, now money for a ticket.
> "Someone who truly loves you does not ask for money before meeting you."

### 1:50–2:35 · Speaker A · The hidden guard
*(Watcher already running hidden, notifier running. Teammate sends the prepared message from an unsaved number to the demo WhatsApp.)*
> But she will not paste anything. So 2nd Eye also watches for her.
> A hidden browser keeps her WhatsApp Web open.
> It reads only chats from numbers she has not saved.
> Saved contacts are not analysed at all. Only a tiny tripwire checks them for codes, card data, remote access or money.
> A stranger just wrote to her.
*(Overlay appears: screen dims, card in the middle.)*
> The whole screen dims. A card she cannot miss. She has to press "Am înțeles".
> No message text in the alert, no link, no number.

### 2:35–3:00 · Speaker B · How it decides, and handoff
> How does it decide? Four signals, all on this laptop.
> Romanian rules, link and number checks against the official catalog, a small local AI model that must quote its evidence, and per-flag calibration.
> Nothing goes to the cloud. Same input, same answer, every time.
> It is not perfect, and we will tell you where.
> Now the dashboard with your Test Set. *(Switch to tab "Tablou de rezultate".)*

Rehearse with a stopwatch. If over time, cut the "Sună pe cineva de încredere" line first, then the read-aloud line.

---

## 2. Demo run order (exact clicks) and fallbacks

**Before the slot (10 min):** follow the "Jury checklist" in `README.md`. Short form:
1. Stop watcher and notifier while the dashboard is built (command in README), then double-click `run.bat`. `lms ps` must show PARALLEL 1, CONTEXT 8192. Status dot = model on.
2. Copy the Test Set folder outside the repo. "Tablou de rezultate" → "Încarcă un dosar" → wait for all rows → "Export CSV" (backup).
3. **Do not restart the server** until the review is over (the in-memory memo guarantees the live re-run equals the dashboard row).
4. Restart the watcher hidden and the notifier for the live part (`integrations\notifier\start_all.ps1` or by hand). Do this only after all dashboard rows exist.
5. Open three browser tabs or keep text ready in a local text file: the SMS for step B, the romance thread for step C. Use team-written examples, never validation or Test Set text.

| # | Who | Clicks | If it fails |
|---|---|---|---|
| 1 | B | Tab **Verifică un mesaj** → paste SMS → **Verifică mesajul** | **Model down** (status dot yellow): keep going. Rules + link/number checks still give the verdict and warning. Say: "the AI model is off, rules-only mode still protects her." |
| 2 | B | **Citește cu voce tare** (then **Oprește citirea**) | No sound: read the warning yourself from the screen; mention the button. |
| 3 | C | Tab **Importă o conversație** → paste thread → under **Care dintre aceștia sunteți dumneavoastră?** pick our side → check the preview (you on the right, grey) → **Verifică conversația** → scroll to the card **Semnele unei povești de dragoste false** | Parser shows wrong sides: use the "plain" path (paste a single message, **Verifică mesajul primit**) or load the thread as a scenario JSON with **Deschide fișier** in the first tab. Card missing: point at the red flags and the warning instead. |
| 4 | A | Teammate sends the message from an unsaved number → wait for the overlay (watcher polls every 20 s) → **Am înțeles** | **Watcher not catching** (logged out, selector change, slow poll): go to tab **Importă o conversație** and paste the same message; say "the same detector, the same warning". Backup: `python integrations\watcher\watcher.py --demo --show` shows the demo WhatsApp page with the in-page banner; `integrations\notifier\notifier.py --test --auto-close 5` shows the overlay with sample text. |
| 5 | B | Tab **Tablou de rezultate** (already loaded) → click a row → detail | Rows missing: load the folder again (memo returns identical results instantly for files already analysed). Last resort: open the exported CSV. |

**Wi-Fi fails:** nothing changes. The detector, model, GUI and notifier all run on this laptop (`localhost`). Only the live WhatsApp step needs internet; use the import-tab fallback.
**Laptop GPU busy or LM Studio crashes:** the app keeps working in rules-only mode; do not restart the server during review unless you must (a restart clears the memo; results are deterministic anyway, but say so if you restart).

---

## 3. The architect's question

*"How does your detector decide, and does any message leave your laptop for a cloud AI service?"*

> 1. No message ever leaves the laptop: the only model is a 4B Qwen running in LM Studio on `localhost:1234`, and `backend/llm.py` refuses any LLM URL whose host is not localhost, 127.0.0.1 or ::1.
> 2. The decision is an ensemble: Romanian intent rules, link and phone/e-mail checks against the official catalog, and the local model, whose flags count only if their evidence quote really appears in that message and they pass a per-flag threshold in `calibration.json`.
> 3. Accepted flags go into the official points formula message by message, which gives the verdict, the scam type and the first-alert message, and the Romanian warning comes from fixed templates, never from the model.
> 4. It is deterministic (temperature 0, top_k 1, fixed seed, one model slot), and an in-memory memo keyed by a hash of the scenario makes a live re-run return exactly the dashboard row; with the model off it still runs on rules and link checks.

---

## 4. Honest limits (say these, briefly)

- **Single romance ask stays amber.** With the official points, one love-plus-money message (emotional pressure 10 + payment request 25 = 35) is SUSPICIOUS, not SCAM, unless secrecy, a new number or a suspicious link adds points. We follow the official formula instead of inflating it.
- **Live reading is checked only on WhatsApp.** The watcher's selectors for Messenger, Instagram, Telegram and Gmail are not verified on real accounts; Messenger and Instagram are shown on our demo pages, because Meta's terms forbid automated access.- **The Android app is built but untested on a device.** `android-webwatcher` compiles to an APK; injection, background service and alerts have not run on a phone or emulator. It also needs the laptop on the same Wi-Fi.
- **The fine-tune is not shipped.** Data (1,170 synthetic training threads plus the converted teammate data), scripts and toolchain are ready, but the GPU was full with the live model, so no fine-tuned model or comparison exists. We ship the base 4B model.
- **Romanian text only, no voice calls yet.** Call transcripts work as text; live call listening is roadmap. The catalog is the hackathon's fictional one.

---

## 5. Likely jury questions

**False alarms?** A genuine organisation message with only official links and nothing requested gets zero flags (genuine-message guard). The model cannot add a flag without an exact quote and a calibrated threshold. We tested on team-written genuine-but-scary messages (delivered codes, real bank notices). Early false alerts are the worst case, so the first alert must land on the right message.

**Privacy?** Text never leaves the laptop, is never logged or written to disk. The memo is RAM only, max 256 results, cleared by `DELETE /api/memo` or a server stop. Alerts carry no message text, links or numbers. No CDNs, fonts or analytics.

**Why only unknown numbers?** Data minimisation: we do not read her private chats with family. Most scams start from a stranger ("new number", courier, bank). In the GUI and the dashboard everything is analysed fully; the gate applies only to live watching.

**What if a known contact is hacked?** Saved contacts still pass a tiny tripwire: a request for a code, card or ID data, remote access or money triggers the full analysis. Known contact is never treated as proof of safety (account takeover case).

**Cost and hardware?** One laptop. The model is a 4B instruct model in LM Studio, about 2 s per scenario on an RTX 3080. No subscription, no API bill. Without a GPU, rules-only mode (`?use_llm=false`, or the watcher's `--lite`) runs on any PC.

**Why not just a big cloud model?** Privacy for the elderly, and the rules forbid it. A small model is enough because rules and link checks carry most of the score; the model only adds quoted evidence.

**Who wrote the warnings?** Fixed Romanian templates, formal "dumneavoastră", at most three short sentences, one action through an official channel from the catalog. Never a link or number from the message, never an invented number.

**Teamwork?** Split by file ownership: detector, server and model, GUI, watcher and notifier, Android, training data. Raul built a separate Android alert app, an engine and training data; see `MERGE.md`.
