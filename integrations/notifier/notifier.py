"""2nd Eye notifier: native Windows toasts for new SUSPICIOUS / SCAM alerts.

Shows a full-screen-centred overlay card (default, tkinter) and/or a Windows toast (--style). Polls the local status feeds
(default http://127.0.0.1:8010/alerts.json = WhatsApp watcher and http://127.0.0.1:8011/alerts.json = mail watcher;
--source takes several comma-separated URLs, seen ids are kept per source) and raises one
Windows toast per alert id. Run with pythonw for no console window:

    .venv\\Scripts\\pythonw.exe integrations\\notifier\\notifier.py
    .venv\\Scripts\\python.exe  integrations\\notifier\\notifier.py --test

Privacy: only the fields verdict/service/sender/label_ro/warning_ro are used. Nothing is written to disk
about alerts (seen ids live in memory only), nothing is printed except status lines without content.
The only files written are the three small icon PNGs and one HKCU registry key naming the app.
"""
import argparse
import collections
import json
import queue
import threading
import sys
import time
import urllib.request
import zlib
import struct
import datetime
import winreg
from pathlib import Path

HERE = Path(__file__).resolve().parent
ICON_DIR = HERE / "icons"
AUMID = "AlgoR3IthM.ScutulBunicii"
APP_NAME = "2nd Eye"
ATTRIBUTION = "2nd Eye · AlgoR3IthM"
DEFAULT_SOURCE = "http://127.0.0.1:8010/alerts.json,http://127.0.0.1:8011/alerts.json"  # WhatsApp watcher, mail watcher

SERVICES = {"whatsapp": "WhatsApp", "messenger": "Messenger", "instagram": "Instagram",
            "telegram": "Telegram", "gmail": "Gmail"}

TITLES = {
    "SUSPICIOUS": "\U0001F7E0 ⚠ Atenție, verificați înainte să răspundeți",
    "SCAM": "\U0001F534 ✖ Pare o țeăpă! Nu răspundeți",
}
BUTTON = "Am înțeles"


# ---------- icons (pure Python PNG, no Pillow needed) ----------

def _png(path, size, rgb, glyph):
    """Draw a shield with a white '!' (glyph='!') or cross ('x') and write it as RGBA PNG."""
    rows = []
    for y in range(size):
        row = bytearray([0])
        v = y / size
        for x in range(size):
            u = (x / size - 0.5) * 2  # -1..1
            # shield outline: wide top, tapering to a point at the bottom
            half = 0.82 if v < 0.55 else 0.82 * max(0.0, (0.96 - v) / 0.41) ** 0.8
            inside = 0.06 <= v <= 0.96 and abs(u) <= half
            px = (0, 0, 0, 0)
            if inside:
                px = rgb + (255,)
                if glyph == "!":
                    if (abs(u) < 0.11 and 0.24 <= v <= 0.58) or (abs(u) < 0.13 and 0.66 <= v <= 0.78 and ((u) ** 2 + ((v - 0.72) * 2) ** 2) < 0.02):
                        px = (255, 255, 255, 255)
                elif glyph == "x":
                    a, b = u, (v - 0.46) * 2
                    if abs(a) < 0.5 and abs(b) < 0.5 and (abs(a - b) < 0.14 or abs(a + b) < 0.14):
                        px = (255, 255, 255, 255)
            row += bytes(px)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    path.write_bytes(png)


def ensure_icons():
    try:
        ICON_DIR.mkdir(exist_ok=True)
        spec = {"app.png": ((30, 94, 168), "!"), "suspicious.png": ((230, 120, 0), "!"),
                "scam.png": ((200, 25, 35), "x")}
        for name, (rgb, glyph) in spec.items():
            if not (ICON_DIR / name).exists():
                _png(ICON_DIR / name, 192, rgb, glyph)
    except Exception:
        pass
    return {k: ICON_DIR / f"{k}.png" for k in ("app", "suspicious", "scam")}


# ---------- toast plumbing ----------

def register_aumid(icon):
    """Per-user registration so toasts are attributed to '2nd Eye' (HKCU, no admin needed)."""
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\AppUserModelId\\" + AUMID)
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
        if icon.exists():
            winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, str(icon))
        winreg.SetValueEx(key, "ShowInSettings", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


class Notifier:
    def __init__(self, scam_scenario="reminder"):
        from windows_toasts import (InteractableWindowsToaster, ToastScenario)
        self.icons = ensure_icons()
        self.registered = register_aumid(self.icons["app"])
        self.toaster = InteractableWindowsToaster(APP_NAME, AUMID if self.registered else None)
        self.scenario = {"reminder": ToastScenario.Reminder, "urgent": ToastScenario.Important,
                         "alarm": ToastScenario.Alarm}[scam_scenario]
        self.keep = []  # keep toast objects alive so handlers keep firing
        self.last_result = None

    def show(self, verdict, service, sender, warning):
        from windows_toasts import (Toast, ToastDisplayImage, ToastSystemButton, ToastSystemButtonAction,
                                    ToastAudio, ToastScenario, ToastDuration)
        scam = verdict == "SCAM"
        svc = SERVICES.get(str(service).lower(), str(service).title())
        line1 = f"Mesaj pe {svc} de la {sender}"
        result = {"failed": None}

        def on_fail(args):
            result["failed"] = str(getattr(args, "reason", "failed"))

        t = Toast(
            text_fields=[TITLES[verdict], line1, warning],
            audio=ToastAudio(),  # default notification sound
            attribution_text=ATTRIBUTION,
            scenario=self.scenario if scam else ToastScenario.Default,
            duration=ToastDuration.Long if scam else ToastDuration.Default,
            on_failed=on_fail,
        )
        icon = self.icons["scam" if scam else "suspicious"]
        if icon.exists():
            t.AddImage(ToastDisplayImage.fromPath(str(icon), altText=verdict))
        t.AddAction(ToastSystemButton(ToastSystemButtonAction.Dismiss, BUTTON))
        self.toaster.show_toast(t)
        self.keep.append(t)
        del self.keep[:-20]
        # show_toast returns None; Windows raises on malformed/blocked toasts, handled by caller.
        time.sleep(0.5)
        self.last_result = result
        return result


# ---------- overlay (tkinter, standard library) ----------

def make_dpi_aware():
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


class Overlay:
    """Borderless always-on-top alert card, centred on the primary screen. Alerts queue, one at a time.
    Must be used from the main thread only."""
    ACTIVE_AFTER_MS = 1500
    REASSERT_MS = 500
    COLORS = {"SCAM": "#B71C1C", "SUSPICIOUS": "#B26A00"}
    GLYPH = {"SCAM": "✖", "SUSPICIOUS": "⚠"}

    def __init__(self, root, auto_close=None):
        import tkinter as tk
        self.tk = tk
        self.root = root
        self.auto_close = auto_close
        self.pending = collections.deque()
        self.done = 0
        self.win = None
        self.back = None
        self.active = False
        self.jobs = []

    def add(self, alert):
        self.pending.append(alert)

    def busy(self):
        return self.win is not None or bool(self.pending)

    def pump(self):
        if self.win is None and self.pending:
            self._show(self.pending.popleft())

    def _after(self, ms, fn):
        self.jobs.append(self.root.after(ms, fn))

    def _show(self, alert):
        tk = self.tk
        verdict = alert["verdict"]
        scam = verdict == "SCAM"
        colour = self.COLORS[verdict]
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        if scam:
            b = tk.Toplevel(self.root)
            b.overrideredirect(True)
            b.configure(bg="black")
            b.attributes("-topmost", True)
            b.attributes("-alpha", 0.6)
            b.geometry(f"{sw}x{sh}+0+0")
            self.back = b
        w = tk.Toplevel(self.root)
        w.withdraw()
        w.overrideredirect(True)
        w.configure(bg=colour)
        w.attributes("-topmost", True)
        card_w = max(520, min(960, int(sw * 0.6)))
        inner = tk.Frame(w, bg="white")
        inner.pack(padx=8, pady=8, fill="both", expand=True)  # 8 px coloured border
        wrap = card_w - 120
        total = self.done + 1 + len(self.pending)

        top = tk.Frame(inner, bg="white")
        top.pack(pady=(24, 8))
        cv = tk.Canvas(top, width=120, height=120, bg="white", highlightthickness=0)
        cv.create_oval(4, 4, 116, 116, fill=colour, outline=colour)
        cv.create_text(60, 62, text=self.GLYPH[verdict], fill="white", font=("Segoe UI Symbol", -72, "bold"))
        cv.pack()
        tk.Label(inner, text=f"{self.GLYPH[verdict]} {TITLE_PLAIN[verdict]}", bg="white", fg=colour,
                 font=("Segoe UI", -38, "bold"), wraplength=wrap, justify="center").pack(padx=40, pady=(8, 8))
        svc = SERVICES.get(str(alert.get("service", "")).lower(), str(alert.get("service", "")).title())
        sender = alert.get("sender", "") or "necunoscut"
        tk.Label(inner, text=f"Mesaj pe {svc} de la {sender}", bg="white", fg="#222222",
                 font=("Segoe UI", -26), wraplength=wrap, justify="center").pack(padx=40, pady=(4, 8))
        tk.Label(inner, text=alert.get("warning_ro", ""), bg="white", fg="#111111",
                 font=("Segoe UI", -26), wraplength=wrap, justify="center").pack(padx=40, pady=(8, 16))
        self.btn = tk.Button(inner, text=BUTTON, font=("Segoe UI", -30, "bold"), bg="#BDBDBD", fg="#757575",
                             disabledforeground="#757575", activebackground=colour, activeforeground="white",
                             relief="flat", padx=48, pady=14, state="disabled", takefocus=0,
                             command=self._click)
        self.btn.pack(pady=(4, 8))
        foot = tk.Frame(inner, bg="white")
        foot.pack(fill="x", padx=20, pady=(4, 12))
        tk.Label(foot, text=ATTRIBUTION, bg="white", fg="#666666", font=("Segoe UI", -16)).pack(side="left")
        if total > 1:
            tk.Label(foot, text=f"{self.done + 1} din {total}", bg="white", fg="#666666",
                     font=("Segoe UI", -16)).pack(side="right")

        w.update_idletasks()
        cw, ch = w.winfo_reqwidth(), w.winfo_reqheight()
        w.geometry(f"{cw}x{ch}+{(sw - cw) // 2}+{(sh - ch) // 2}")
        w.deiconify()
        w.update()
        w.geometry(f"+{(sw - w.winfo_width()) // 2}+{(sh - w.winfo_height()) // 2}")
        self.win = w
        self.active = False
        w.protocol("WM_DELETE_WINDOW", lambda: None)
        w.bind("<Key>", self._key)
        w.lift()
        w.focus_force()
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)  # system alert sound, once
        except Exception:
            pass
        self._after(self.ACTIVE_AFTER_MS, self._activate)
        self._after(self.REASSERT_MS, self._reassert)
        if self.auto_close:
            self._after(int(self.auto_close * 1000), self.dismiss)

    def _activate(self):
        if self.win is None:
            return
        self.active = True
        self.btn.config(state="normal", bg="#1B5E20", fg="white")

    def _reassert(self):
        if self.win is None:
            return
        try:
            if self.back is not None:
                self.back.attributes("-topmost", True)
                self.back.lift()
            self.win.attributes("-topmost", True)
            self.win.lift()
        except Exception:
            pass
        self._after(self.REASSERT_MS, self._reassert)

    def _key(self, ev):
        # Escape never closes; Enter/Space only count once the button is active.
        if self.active and ev.keysym in ("Return", "space", "KP_Enter"):
            self.dismiss()
        return "break"

    def _click(self):
        if self.active:
            self.dismiss()

    def dismiss(self):
        if self.win is None:
            return
        for j in self.jobs:
            try:
                self.root.after_cancel(j)
            except Exception:
                pass
        self.jobs = []
        for x in (self.win, self.back):
            if x is not None:
                try:
                    x.destroy()
                except Exception:
                    pass
        self.win = self.back = None
        self.active = False
        self.done = self.done + 1 if self.pending else 0


TITLE_PLAIN = {"SUSPICIOUS": "Atenție, verificați înainte să răspundeți",
               "SCAM": "Pare o țeăpă! Nu răspundeți"}


# ---------- polling ----------

def fetch(url):
    with urllib.request.urlopen(url, timeout=4) as r:
        return json.loads(r.read().decode("utf-8")).get("alerts", [])


def is_recent(iso, minutes=15):
    try:
        d = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        now = datetime.datetime.now(d.tzinfo) if d.tzinfo else datetime.datetime.now()
        return (now - d).total_seconds() < minutes * 60
    except Exception:
        return False


def poll_loop(source, interval, emit):
    """Worker thread: only hands new alerts to emit(); never touches the UI. Seen ids in memory only."""
    seen = set()
    first = True
    while True:
        try:
            alerts = fetch(source)
        except Exception:
            time.sleep(interval)  # watcher not up yet: stay quiet
            continue
        fresh = [a for a in reversed(alerts) if isinstance(a, dict) and a.get("id") not in seen]
        fresh.sort(key=lambda a: a.get("verdict") != "SCAM")  # SCAM first
        for a in fresh:
            seen.add(a.get("id"))
            if a.get("verdict") not in TITLES:
                continue
            if first and not is_recent(a.get("time")):
                continue  # old alerts from before startup: do not replay
            emit(a)
        first = False
        time.sleep(interval)


SAMPLES = [
    {"verdict": "SCAM", "service": "whatsapp", "sender": "Mama (număr nou)",
     "warning_ro": "Aceasta pare o țeăpă. Nu trimiteți bani și nu răspundeți. "
                   "Sunați-vă fiul sau fiica la numărul pe care îl știți."},
    {"verdict": "SUSPICIOUS", "service": "gmail", "sender": "Banca Exemplu",
     "warning_ro": "Mesajul cere date personale. Nu apăsați pe linkuri. "
                   "Sunați banca la numărul de pe card."},
]


def main():
    ap = argparse.ArgumentParser(description="2nd Eye Windows notifier")
    ap.add_argument("--source", default=DEFAULT_SOURCE,
                    help="alerts.json URL, or several comma-separated (default: watcher 8010 + mail 8011)")
    ap.add_argument("--interval", type=float, default=3.0, help="poll seconds")
    ap.add_argument("--style", default="overlay", choices=["overlay", "toast", "both"],
                    help="overlay = full alert card in the middle of the screen (default); toast = Windows toast; both")
    ap.add_argument("--scam-scenario", default="reminder", choices=["reminder", "urgent", "alarm"],
                    help="toast scenario for SCAM (reminder = stays until dismissed)")
    ap.add_argument("--auto-close", type=float, default=None, metavar="SECONDS",
                    help="close each overlay after N seconds (testing only)")
    ap.add_argument("--test", action="store_true", help="show one sample SCAM and one SUSPICIOUS alert, then exit")
    a = ap.parse_args()

    make_dpi_aware()
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    ov = Overlay(root, a.auto_close) if a.style in ("overlay", "both") else None
    nt = Notifier(a.scam_scenario) if a.style in ("toast", "both") else None
    inbox = queue.Queue()

    def deliver(al):
        if ov:
            ov.add(al)
        if nt:
            try:
                nt.show(al["verdict"], al.get("service", ""), al.get("sender", "") or "necunoscut",
                        al.get("warning_ro", ""))
            except Exception as e:
                print("toast error:", type(e).__name__, file=sys.stderr)

    state = {"t0": time.time()}

    def tick():
        try:
            while True:
                deliver(inbox.get_nowait())
        except queue.Empty:
            pass
        if ov:
            ov.pump()
        if a.test and not inbox.qsize() and not (ov and ov.busy()) and time.time() - state["t0"] > (0.5 if ov else 4):
            root.quit()
            return
        root.after(200, tick)

    if a.test:
        for s in SAMPLES:
            inbox.put(s)
    else:
        # one worker per source, each with its own seen ids (memory only)
        for src in [s.strip() for s in a.source.split(",") if s.strip()]:
            threading.Thread(target=poll_loop, args=(src, a.interval, inbox.put), daemon=True).start()
    root.after(100, tick)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
