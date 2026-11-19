# 2nd Eye: Gmail mail watcher (IMAP)

Reads Gmail over IMAP with an app password, entirely from this laptop: mail goes from Google to the laptop
(`imap.gmail.com:993`, TLS), the analysis is done by the local detector API (`localhost:8000`). Nothing is sent anywhere else.
No browser, no scraping of Gmail's web page.

## Setup (five steps)

1. Google Account (myaccount.google.com) → **Security** → turn on **2-Step Verification**.
2. Open **https://myaccount.google.com/apppasswords**, type a name (e.g. `2nd Eye`), press **Create**, copy the 16 characters.
3. Copy `.env.example` to `.env` in the project root (it is git-ignored) and fill in
   `GMAIL_ADDRESS=...@gmail.com` and `GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx`.
4. Optional: put addresses she trusts but has never written to in `integrations/mail/trusted.txt`, one per line (git-ignored).
5. Start the detector API (`run.bat`), then the mail watcher, then the notifier (it polls 8010 and 8011 by default).

## Run

```powershell
.venv\Scripts\python.exe integrations\mail\mail_watcher.py              # last 7 days, then new mail every 30 s
.venv\Scripts\python.exe integrations\mail\mail_watcher.py --no-llm     # rules only (use_llm=false)
.venv\Scripts\pythonw.exe integrations\notifier\notifier.py             # Windows alert for SUSPICIOUS / SCAM
```

Flags: `--days N` (default 7), `--interval S` (default 30), `--api URL` (default http://localhost:8000),
`--status-port` (default 8011), `--max-threads` (default 150, newest first), `--once` (one pass, then exit).
Status page: http://127.0.0.1:8011 (only SUSPICIOUS and SCAM threads); feed: http://127.0.0.1:8011/alerts.json
(same shape as the WhatsApp watcher on 8010, `service` = `gmail`). If `.env` is missing, the watcher prints
these setup steps in Romanian and English and exits.

## What it does

- On start: INBOX mail from the last N days, grouped by Gmail thread (`X-GM-THRID`); then polls for new mail
  (new INBOX UIDs; her new replies in Sent re-check a watched thread).
- Each thread is one scenario (`channel: "email"`): the other person's mails are `sender`, her replies (from the
  Sent folder, found by its `\Sent` flag, so localised names work) are `reader`, in date order.
  Text = subject (first message) + plain-text body (HTML converted to text if there is no plain part), with
  quoted replies (`On … wrote:`, `În … a scris:`, `>` lines, Outlook header blocks), signatures and phone footers
  removed; at most ~2000 characters per message, last 30 messages per thread.
- Trust Circle: a sender is **known** if she ever mailed that address (Sent folder searched once per address,
  cached in memory) or the address is in `trusted.txt`. Known → `known_contact: true` + `?trust_gate=true`
  (tripwire only). Unknown → full analysis. A thread with several outside people is known only if all are.
- Skips her own mail and system mail with no text at all.

## What is read and what is never stored

- Read-only: mailboxes are opened with EXAMINE and bodies fetched with `BODY.PEEK`, so nothing is marked as read.
  Nothing is ever sent, moved, deleted or flagged.
- Mail text lives in memory only while one thread is analysed and is sent only to the local API.
  It is never written to disk, printed or logged. Console lines: `[gmail] VERDICT score #shorthash`.
- Kept in memory (lost on exit): verdict, score, sender display name, the Romanian warning (for the status page).
- The password is read from `.env` and never printed.

## Limits

- App passwords require 2-Step Verification. Accounts using only passkeys / Advanced Protection may not offer them.
- Google Workspace (school / company) accounts: the admin may have disabled IMAP or app passwords.
- Gmail only (uses Gmail's `X-GM-THRID` extension). Polling, not push: up to `--interval` seconds delay.
- Attachments and images are not analysed; only the first ~1.5 MB of each message is fetched.
- The start-up scan (last N days) fills the status page, but `/alerts.json` answers 503 until that scan is done and each
  alert's `time` is the date of the newest mail in the thread, so the notifier (which skips alerts older than
  15 minutes on its first read) does not pop up for old mail. New mail after start-up does pop up.
- The detector was tuned on SMS / chat scenarios: newsletters and notification mails with links from unknown
  senders often come out SUSPICIOUS. Add such senders to `trusted.txt` if they are noisy.
