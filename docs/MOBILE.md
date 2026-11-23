# Mobile version (Android) and its engine

The phone half of 2nd Eye, built by Raul (Moghedien-ux) during the hackathon: an Android app that watches WhatsApp on the phone and
pops a full-screen warning over it, plus a Python "neuro-symbolic" engine with its own fine-tuned small model. Source:
[`mobile/android/`](../mobile/android) and [`mobile/engine/`](../mobile/engine). Training data: [`Nou Raul/train_data.jsonl`](../Nou%20Raul/train_data.jsonl).

## How the app works

| Piece | File | What it does |
|---|---|---|
| WhatsApp watcher | `WhatsAppMonitorService.kt` | Android **accessibility service** for `com.whatsapp` / `com.whatsapp.w4b`. 500 ms after the screen changes it reads the open chat (contact title + `message_text` nodes), decides who wrote each bubble by its screen position (right side = the user), and analyses the thread. Re-analyses only when the last three sender messages change. |
| Rules engine | `LocalScamEngine.kt` | Deterministic scoring in < 5 ms: red-flag points, scam type and Romanian warning, with links checked against the **official catalog** bundled as `assets/official_catalog.json` (real bank/courier/authority domains and phone numbers). |
| On-device model | `OnDeviceLlm.kt` + `cpp/llama_jni.cpp` | JNI bridge to **llama.cpp**: loads `scamshield-3b.gguf` from the app's private storage (n_ctx 1024, 4 threads) and returns JSON. Used only to *add* an alert when the rules said SAFE, never to silence one. |
| Model import | `MainActivity.kt` | Status screen (accessibility on? overlay allowed? model loaded?) and a button to pick the `.gguf` from the phone's files; it is copied into private app storage. Without a model the app runs in "Mod Rapid" (rules + catalog). |
| Alert | `OverlayAlertManager.kt` | Earthquake-alert style overlay (`TYPE_APPLICATION_OVERLAY`) with verdict, score, warning and the official phone number to call. One alert per contact per risk signature every 2 minutes. |

Permissions: accessibility service (reads WhatsApp's screen) and "display over other apps" (the alert). **No internet permission**:
nothing the app reads can leave the phone. `allowBackup="false"`, so app data (including the model) is not copied to cloud backups.

## The engine (`mobile/engine/`)

`engine.py` → `analyze_scenario(scenario)` takes the same scenario JSON as the official validation files and returns
`verdict`, `scam_type`, `risk_score`, `first_alert`, `red_flags`, `warning_ro`: catalog-driven rules first, then the fine-tuned model
through **Ollama** (`scamshield-3b:latest` on `localhost:11434`, temperature 0, seed 42) as a fallback for the scam type.
`server.py` (FastAPI) serves `/analyze`, `/analyze-batch`, a live WebSocket feed `/ws/live` and `dashboard.html`.
`stress_test.py` is a 100-case seeded benchmark (40 SAFE + 60 scam); `test_validation.py` checks the 11 validation scenarios.

```
pip install -r mobile/engine/requirements.txt
cd mobile/engine && uvicorn server:app --port 8000      # binds 127.0.0.1 by default
```

## The model: scamshield-3b

- A small Qwen model fine-tuned by Raul for this task (the team recalls **Qwen2.5**; the file name says 3B). It runs in Ollama
  on a laptop and as a GGUF inside the Android app.
- **Training data:** `Nou Raul/train_data.jsonl`: 600 rows in Alpaca format (`instruction`, `input`, `output`), 289 distinct
  inputs. 261 genuine (`NONE`) and 339 scams across 11 types (BANK_IMPERSONATION 63, FAMILY_EMERGENCY 58, TECH_SUPPORT 33,
  ACCOUNT_TAKEOVER 32, COURIER_FEE 30, ROMANCE 21, INVESTMENT 21, PRIZE_LOTTERY 21, JOB_OFFER 21, MARKETPLACE 20,
  AUTHORITY_IMPERSONATION 19). Input = `Channel | Sender (address, known)` header plus `[n] (sender|reader): text` lines;
  output = JSON `{red_flags, scam_type, warning_ro, official_suggestion}`. `engine.py` prompts with exactly this format.
- **Not in this repository yet:** the GGUF weights, the exact base checkpoint, and the fine-tuning script/notebook and its
  settings. They are on Raul's machine. Large weights belong in a GitHub Release or on Hugging Face, not in git.

## Known gaps (found 2026-11-23, not fixed)

1. **The on-device model is not built into the APK.** `CMakeLists.txt` expects a `llama.cpp/` source folder next to it, which
   is not in the project, and `app/build.gradle.kts` has no `externalNativeBuild` block. The release APK built at the hackathon
   contains no `libscamshield_llm.so`, so loading the model fails (caught) and the app runs on rules + catalog only.
2. **Prompt mismatch.** The phone's prompt (ChatML, Romanian system prompt) asks for `{"verdict", "scam_type", "warning_ro"}`,
   but the model was trained on the Alpaca prompt above, whose answers have no `verdict` key. The app reads a missing
   `verdict` as SAFE, so the model would likely never raise an alert on the phone. Fix: send the same prompt as `engine.py`
   and derive the verdict from `red_flags` with the catalog points.
3. **The model writes its own warning text.** The desktop app only uses fixed templates (`backend/warnings_ro.py`) so a warning
   can never repeat a scammer's number or link; the phone shows `warning_ro` from the model as-is.
4. `local.properties`, `.idea/`, `.cxx/`, `build-native/`, the release APK and an older duplicate of `OverlayAlertManager.kt`
   (outside the source set) were deliberately not copied from the original folder.

## Security changes made when publishing (2026-11-23)

- Android: removed the unused `INTERNET` permission, `usesCleartextTraffic="true"` and the unused OkHttp dependency; the model's
  raw output (which can quote messages) is no longer written to logcat, only its length.
- Engine server: CORS was `*` and `/ws/live` accepted any origin. WebSockets are not covered by CORS, so any website open in
  the browser could have connected and received every analysed conversation. CORS and the WebSocket are now limited to
  `http://localhost` / `http://127.0.0.1` origins (tested: dashboard 101, foreign origin 403, no origin 403).
