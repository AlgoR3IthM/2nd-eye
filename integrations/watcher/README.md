# Watcher - 2nd Eye

One Chromium instance with its own saved profile watches the web versions of WhatsApp, Messenger, Instagram direct,
Telegram Web and Gmail. A reader script per service hands what it sees to Python (exposed binding, because the sites'
CSP blocks calls to localhost); Python asks the local detector (`http://localhost:8000`) and keeps the latest results
for a local status page. Message text goes only to the local API: it is never printed, logged, stored or served.
Console output is service, verdict and score only.

## Install

```
uv pip install --python .venv\Scripts\python.exe playwright
```
Google Chrome or Edge, if installed, is used automatically. Otherwise: `.venv\Scripts\python.exe -m playwright install chromium`.
Start the detector first: `.venv\Scripts\python.exe -m uvicorn backend.server:app --host 127.0.0.1 --port 8000`.

## Run

| What | Command |
|---|---|
| First run: a relative signs in once (WhatsApp QR code, Google, ...) | `python integrations\watcher\watcher.py --login` |
| Normal run: no visible window (new headless mode, same profile) | `python integrations\watcher\watcher.py` |
| Same, if a site refuses headless: real window parked off-screen | `... --hidden-window` |
| Visible, with the in-page warning banner (demo) | `... --show` |
| Whole demo, no accounts needed | `python integrations\watcher\watcher.py --demo --show` |
| Low-end PC | `python integrations\watcher\watcher.py --lite` |

(Use `.venv\Scripts\python.exe` for `python`.) Other flags: `--services whatsapp,gmail`, `--browser chrome|msedge|chromium`,
`--api URL`, `--poll SECONDS` (chat-list poll, default 20), `--status-port` (default 8010), `--minimized` (with `--show`).
The profile lives in `integrations/watcher/.profile/<browser>` (git-ignored); logins survive restarts.
`--login` closes with the window; it does no analysis. The browser is started without the automation switch and with
`--disable-blink-features=AutomationControlled`; in headless mode the "Headless" part of the user agent is removed.

## How it works

* **Background mode (default)** - nobody opens conversations in a hidden browser, so each reader has a `list()` that reads
  the chat or inbox list without clicking: unread rows only, sender, stranger or not, and the preview text the list shows.
  Polled on a timer and on DOM changes. Each preview becomes a one-message scenario for `/api/analyze`; a saved contact is sent
  with `?trust_gate=true` (tripwire only). The same preview is never analysed twice.
* **Conversation reading** - when a conversation *is* open (`--show`, or after `--open-strangers`) the reader's `scan()` reads
  the whole thread (last 30 messages) and, in `--show`, draws the banner: verdict colour, icon, official Romanian label,
  the API's `warning.ro` at 22 px, "Am inteles" and "Il cunosc" buttons; a small tick for SAFE; the first-alert message gets an
  outline. The banner never shows links or numbers from the conversation.
* **Trust Circle** - the reader decides stranger or known from what the service shows (WhatsApp: a bare number as chat title;
  Messenger and Instagram: message requests; Gmail: no earlier reply from you in the thread; Telegram: the "Add to contacts /
  Report spam" bar, and in the list every unread chat counts as stranger). "Il cunosc" adds the identifier to
  `trusted.json` (identifiers only, git-ignored). Marking is possible with `--show`; in background mode edit the file by hand
  (`{"whatsapp": ["+40712345678"], "gmail": ["name@example.com"]}`, digits and lower case, no spaces).
* **`--open-strangers` (opt-in)** - opens an unread conversation, only when the sender is a stranger, to read the full thread.
  **This marks the chat as read on her phone**, so she could miss a real message from that person. Off by default.
* **Status page** - `http://127.0.0.1:8010` (large type, Romanian, colour + icon + words, refreshes every 5 s). Alerts live in memory
  only: service, sender display name, verdict, score, the API's `warning.ro`, time. No message text.
  `GET http://127.0.0.1:8010/alerts.json` returns
  `{"alerts": [{"id", "time" (ISO local), "service", "sender", "verdict", "risk_score", "label_ro", "warning_ro"}]}`,
  newest first, at most 50, SAFE results included. `id` is a hash of service + sender + verdict + conversation state, so it changes
  when the conversation changes. Intended for a notifier on the same PC.
* **Ctrl+Shift+S** on any watched page shows counts only: header found, messages found, incoming, outgoing, known or stranger,
  list rows / unread / strangers. Use it to fix selectors on real accounts.

## Low-end PC (`--lite`)

* one tab, rotating through the selected services every `--rotate` seconds (default 60; WhatsApp needs ~20 s to load)
* in background mode images, media and fonts are blocked (not in `--login`: QR code and login pages need them)
* `use_llm=false` is sent to the API (rules and link checks only), plus a few Chromium memory flags
* memory-friendly defaults: `--lite --services whatsapp,gmail --poll 30 --rotate 90`; fewer services = less RAM (each tab is roughly 200-400 MB)

## Demo

`python integrations\watcher\watcher.py --demo --show` serves `demo/*.html` on a random local port and opens one tab per
service. Each page mimics the service DOM: a chat list with three unread chats (a scam from a stranger, a harmless saved contact,
a saved contact asking for a code). The list is polled at once (see the status page and the console); click a chat to
see the banner. `--open-strangers` makes the watcher open the stranger's chat itself. `?c=0|1|2` opens a chat directly.

## Add a sixth service

Drop `readers/<name>.js`. First line: `// @service <name> <start url>`. Then
`window.__SB.register({ name, channel, hostnames: [...], scan, list })`:
`scan()` returns `null` or `{header, sender:{name,address}, known_contact, rows:[{from:"sender"|"reader", text, el}]}`;
`list()` returns `[{name, address, stranger, preview, unread, el}]`. Keep selectors in one `SEL` block, fail silently, use only
`createElement`/`textContent`. Add `demo/<name>.html` with `<meta name="sb-demo" content="<name>">` for the demo. `watcher.py` finds it by itself.

## Honest limits

* **Selectors are unverified on live accounts.** They are written from knowledge of each site's DOM; expect to adjust them (Ctrl+Shift+S).
  Verified only against the demo pages and the real login pages (no script errors).
* Meta's terms forbid automated access: Messenger and Instagram should be shown on the demo pages, not on a real account.
* Google may still refuse sign-in in an automated browser; use `--login` (visible), then `--hidden-window` if headless is refused.
* List previews are what the page shows and may be truncated by the site; a scam that only shows in later messages needs the open conversation.
* Telegram and Gmail lists cannot tell a saved contact from a stranger, so unread rows are scanned in full (still local only).
* Only unread rows (list) or the open conversation are read; nothing is clicked unless `--open-strangers` is set.
* Alerting the grandmother herself is out of scope: results appear on the status page and `/alerts.json`.
* The only network destinations of this program are the five services and the local API (`127.0.0.1`); the demo and status servers listen on 127.0.0.1 only.
