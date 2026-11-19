# 2nd Eye (Scam Shield) by AlgoR3IthM

## Run

1. Double-click `run.bat` (starts the LM Studio server, loads the model, starts the API, opens http://localhost:8000).
2. From a phone on the same Wi-Fi open `http://<laptop-ip>:8000`.
3. Without the LLM: open `/` and the app still works (rules + link/number checks); the API takes `?use_llm=false`.

Settings (environment variables): `SCAMSHIELD_MODEL` (default `qwen/qwen3-4b-2507`, 4B, about 2 s per scenario on the RTX 3080; 11 validation scenarios in about 25 s), `SCAMSHIELD_LLM_URL` (default `http://localhost:1234`, must be localhost), `SCAMSHIELD_GPU`, `SCAMSHIELD_CTX`.
Manual start: `.venv\Scripts\python.exe -m uvicorn backend.server:app --host 0.0.0.0 --port 8000 --no-access-log`.

## Architecture

- `web/index.html`: GUI and results dashboard (one self-contained file, no CDN).
- `backend/server.py`: FastAPI, `/api/analyze`, `/api/analyze-text`, `/api/health`, `/api/catalog`; one analysis at a time.
- `backend/fusion.py`: ensemble, official scoring formula, verdict, first alert.
- `backend/rules.py`: Romanian intent rules (Signal A).
- `backend/contacts.py`: links and numbers against the official catalog (Signal B).
- `backend/llm.py`: local LLM (Signal C) via LM Studio, JSON-schema output, evidence quotes validated against the text.
- `backend/patterns.json`: Romanian example patterns retrieved into the LLM prompt by token overlap.
- `backend/warnings_ro.py`: fixed Romanian warning templates (the LLM never writes warnings).
- `integrations/`: Telegram forwarding bot and WhatsApp Web browser extension, both calling this local API.
- Deterministic: temperature 0, top_k 1, seed 42, no randomness, so a re-run gives the same table. LM Studio's prompt cache can change the first tokens of an otherwise identical request, so `llm.py` sends each prompt once with `max_tokens=1` first, which makes the answer independent of what was analysed before. A failed LLM call is retried twice; if it still fails the result says `signals.llm_status: "unavailable"` and `/api/health` shows `llm: false`.
- Check it: `python backend/evaluate.py --repeat 5` (and `--selftest --repeat 5`) runs every scenario five times and lists any field that differs (ids and field names only).

## Does any message leave your laptop?

No. Analysis runs on this laptop only: the API listens on the local network, and the only outbound connection from the detector is to LM Studio on `localhost:1234` (the code refuses any other host). No cloud AI is used at runtime, no message text is logged or written to disk, and there are no analytics or external fonts/CDNs. The The server keeps a small in-memory result memo (at most 256 results, keyed by a SHA-256 of the scenario, the model id and the options) so that the same scenario analysed twice in one session returns the identical result. It lives in RAM only, is never written to disk, disappears when the server stops, and `DELETE /api/memo` clears it at any time. The Telegram bot, if used, only receives messages the user forwards to it and sends them to this same local API.
