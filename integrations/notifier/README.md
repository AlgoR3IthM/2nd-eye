# Notifier: how she finds out (Windows)

`notifier.py` runs in the background (no console, use `pythonw`), polls the watcher's feed
`http://127.0.0.1:8010/alerts.json` every 3 seconds and alerts her once per new SUSPICIOUS or SCAM alert id
(seen ids are kept in memory only). Choose the style with `--style overlay|toast|both` (default **overlay**).

## Overlay (default)

A borderless always-on-top card (tkinter, standard library, no extra dependency) centred on the primary screen, like a
system warning. SCAM also dims the whole screen behind the card; SUSPICIOUS shows the card only. The card has a big icon,
the official label in words (✖ red / ⚠ amber, so colour is never the only signal), "Mesaj pe <serviciu> de la <expeditor>",
`warning_ro` as received (26 px, wrapped), the small attribution, and one large button "Am înțeles". The system alert sound
plays once. The button becomes active after 1.5 s; Enter and Space are ignored until then, and Escape never closes it.
It re-asserts topmost every 0.5 s. Several alerts queue and show one at a time ("1 din 3"). The process is DPI-aware.
`--auto-close SECONDS` closes each overlay automatically (testing only).

## Toast (`--style toast` or `both`)

- Title: `🟠 ⚠ Atenție, verificați înainte să răspundeți` or `🔴 ✖ Pare o țeapă! Nu răspundeți`
- Body: `Mesaj pe <Serviciu> de la <expeditor>`, then `warning_ro` exactly as received.
- Footer: `2nd Eye · AlgoR3IthM`, shield icon, default notification sound, one button `Am înțeles` (dismiss).
- SCAM toasts use the toast scenario **reminder**: they stay on screen until she dismisses them.
- Uses only the alert fields (verdict, service, sender, warning). No message text, no links, no phone numbers. Nothing about alerts is written to disk.
- Alerts older than 15 minutes that already exist when the notifier starts are not replayed. SAFE alerts never produce a toast.
- If the watcher is not reachable it keeps polling quietly.

Toasts are raised with the `windows-toasts` package (WinRT, `uv pip install --python .venv\Scripts\python.exe windows-toasts`),
under the app id `AlgoR3IthM.ScutulBunicii` registered for the current user (HKCU, no admin) so Windows names the app
"2nd Eye" and not Python. The icons in `icons/` are generated on first run.

## Test

```powershell
.venv\Scripts\python.exe integrations\notifier\notifier.py --test
```
Shows one sample SCAM and one sample SUSPICIOUS alert (invented text) in the chosen style and exits. For a quick look that
does not block the screen: `... notifier.py --test --auto-close 3`. Other flags:
`--style`, `--source URL`, `--interval SECONDS`, `--scam-scenario reminder|urgent|alarm` (toast only).

## Start everything / autostart

Manual start of the whole stack, hidden (LM Studio + model, API on :8000, watcher if present, notifier):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File integrations\notifier\start_all.ps1
```
Each piece starts only if it is not already running.

Install at sign-in (run from an **elevated** PowerShell; the script says so if you are not elevated):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File integrations\notifier\install_autostart.ps1
```
Without administrator rights: add `-Unelevated`. Remove:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File integrations\notifier\uninstall_autostart.ps1
```
(Remove from an elevated shell if it was installed elevated.) Task name: `ScutulBunicii`; trigger: at logon of the installing user;
restarts up to 3 times on failure; no time limit; runs hidden.

## Why at sign-in and not "as SYSTEM at boot"

Windows runs services and SYSTEM tasks in **session 0**, which has no desktop: a toast raised there is never shown.
The watcher also needs the user's own session and profile (saved logins, the user's browser). So the task must run
as the signed-in user, in her interactive session, with an at-logon trigger. "The second the laptop turns on" therefore
means the second she is signed in. With automatic sign-in configured (`netplwiz`, or the `AutoAdminLogon` policy; this
stores a credential on the machine, so decide that consciously), that is right after boot.

## Administrator rights: a decision for the team

The team asked for highest privileges so nothing prompts at start; the default install does that (RunLevel Highest, no UAC prompt).
Honest note: **nothing in this stack needs administrator rights.** Running a browser-automation process (the watcher drives a browser that is
logged in to her messaging accounts) elevated is a security trade-off: anything that goes wrong in that browser then runs with
admin rights. `-Unelevated` gives the same behaviour with standard rights and is the safer default for real use. Decide before the demo.

## Limits

- The overlay is a normal topmost window: Do Not Disturb cannot hide it, but it cannot draw over the lock screen, the secure desktop (UAC prompts, Ctrl+Alt+Del), or usually an exclusive full-screen game or video. The dimming backdrop covers the primary monitor only.
- Another program that also forces itself topmost can briefly compete; the overlay wins back within half a second.
- The overlay was confirmed by enumerating windows (exists, visible, topmost, centred, 860x550 on a 1920x1080 screen); it was not screenshotted.
- I could confirm that Windows accepted the toasts (no failure event, and they appeared in the notification history with the right scenario) but a script cannot prove they were visible on screen; check once on the real laptop with `--test`.
- Do Not Disturb / Focus Assist can still hold toasts back. The `reminder` scenario persists but does not break through Do Not Disturb; `--scam-scenario urgent` is allowed through Focus by Windows 11 (user can revoke it in Settings) but may not persist. Pick on the target laptop. Notifications must be enabled for "2nd Eye" in Settings.
- Only as good as the watcher: if it is not running or logged out of a service, no alerts arrive. A toast is a prompt to stop and check, not a guarantee.
- Windows only, and only while she is signed in. The task does not stop already running processes when removed.
