"""2nd Eye - AlgoR3IthM: Telegram front door.

Forward a suspicious message to this bot; it asks the LOCAL detector API on
this laptop (http://localhost:8000) and answers in Romanian.

Privacy: no cloud AI, no message text stored or logged. The only state is a
small in-memory list of "known" senders (lost on restart, by design).
"""
import asyncio
import os
import re
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

API = os.environ.get("SCAM_API", "http://localhost:8000")
THREAD_WINDOW = 3.0  # seconds: forwards closer than this form one thread

ICONS = {
    "SAFE": "🟢 ✔ Pare în regulă",
    "SUSPICIOUS": "🟠 ⚠ Atenție, verificați înainte să răspundeți",
    "SCAM": "🔴 ✖ Pare o țeapă! Nu răspundeți",
}
API_DOWN = ("Momentan nu pot verifica mesajul, dar nu s-a întâmplat nimic grav. "
            "Până atunci, nu răspundeți și nu trimiteți bani sau coduri; "
            "sunați o persoană de încredere.")
WELCOME = ("Bună ziua! Sunt 2nd Eye, un ajutor care vă spune dacă un mesaj primit pare o țeapă. "
           "Trimiteți-mi (sau redirecționați-mi) mesajul care vă face să ezitați și vă răspund imediat, "
           "iar mesajul este verificat doar pe acest calculator, nu pe internet.")

URL_RE = re.compile(r"(?:https?://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)+/\S*", re.I)
NUM_RE = re.compile(r"\+?\d[\d\s.\-()]{3,}\d")


def sanitize(reply: str, source: str) -> str:
    """Remove any link or number that also occurs in the analysed message."""
    bad = set(m.group(0).strip() for m in URL_RE.finditer(source))
    bad |= set(m.group(0).strip() for m in NUM_RE.finditer(source))
    for token in sorted(bad, key=len, reverse=True):
        if token and token in reply:
            reply = reply.replace(token, "…")
    # Never emit a bare link either, even if not in the source.
    return URL_RE.sub("…", reply)


def origin_of(msg):
    """Return (key, display_name) of the original sender of a forward, or (None, None)."""
    fo = getattr(msg, "forward_origin", None)
    if fo is None:
        return None, None
    user = getattr(fo, "sender_user", None)
    if user is not None:
        return f"u{user.id}", user.full_name
    hidden = getattr(fo, "sender_user_name", None)
    if hidden:
        return f"h{hidden}", hidden
    return None, None


async def call_api(scenario=None, text=None, trust_gate=False):
    async with httpx.AsyncClient(timeout=60) as client:
        if scenario is None:
            r = await client.post(f"{API}/api/analyze-text",
                                  json={"text": text, "channel": "sms", "known_contact": False})
        else:
            r = await client.post(f"{API}/api/analyze", json=scenario,
                                  params={"trust_gate": "true"} if trust_gate else None)
        r.raise_for_status()
        return r.json()


def build_scenario(texts, name, known):
    return {
        "id": "telegram",
        "channel": "telegram",
        "sender": {"name": name, "address": None, "known_contact": known},
        "messages": [{"n": i + 1, "from": "sender", "text": t} for i, t in enumerate(texts)],
    }


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("Lipsește TELEGRAM_BOT_TOKEN.\n"
              "1. In Telegram, deschideți @BotFather și trimiteți /newbot.\n"
              "2. Alegeți un nume și un utilizator (se termină în 'bot'); primiți un token.\n"
              "3. Copiați integrations/.env.example în .env în rădăcina proiectului și completați:\n"
              "   TELEGRAM_BOT_TOKEN=<token>\n"
              "4. Rulați din nou botul.")
        sys.exit(1)

    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                              ContextTypes, MessageHandler, filters)

    async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(WELCOME)

    async def flush(chat_id, app):
        await asyncio.sleep(THREAD_WINDOW)
        buf = app.bot_data.setdefault("buffers", {}).pop(chat_id, None)
        if not buf:
            return
        texts, key, name = buf["texts"], buf["key"], buf["name"]
        known = key is not None and key in app.bot_data.setdefault("known", set())
        try:
            if len(texts) == 1 and not known:
                res = await call_api(text=texts[0])
            else:
                res = await call_api(scenario=build_scenario(texts, name, known), trust_gate=known)
        except Exception:
            await app.bot.send_message(chat_id, API_DOWN)
            return
        verdict = res.get("verdict", "SUSPICIOUS")
        warning = (res.get("warning") or {}).get("ro", "")
        body = sanitize(f"{ICONS.get(verdict, ICONS['SUSPICIOUS'])}\n\n{warning}", "\n".join(texts))
        markup = None
        if key and not known:
            tokens = app.bot_data.setdefault("tokens", {})
            tok = str(len(tokens) + 1)
            tokens[tok] = key
            markup = InlineKeyboardMarkup(
                [[InlineKeyboardButton("Îl cunosc", callback_data=f"know:{tok}")]])
        await app.bot.send_message(chat_id, body, reply_markup=markup)

    async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        msg = update.message
        text = msg.text or msg.caption
        if not text:
            return
        app = ctx.application
        chat_id = msg.chat_id
        key, name = origin_of(msg)
        buffers = app.bot_data.setdefault("buffers", {})
        buf = buffers.setdefault(chat_id, {"texts": [], "key": key, "name": name, "task": None})
        buf["texts"].append(text)
        if buf["key"] is None and key:
            buf["key"], buf["name"] = key, name
        if buf["task"]:
            buf["task"].cancel()
        buf["task"] = asyncio.create_task(flush(chat_id, app))

    async def on_know(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query
        await q.answer()
        key = ctx.application.bot_data.get("tokens", {}).get(q.data.split(":", 1)[-1])
        if key:
            ctx.application.bot_data.setdefault("known", set()).add(key)
            await q.edit_message_reply_markup(None)
            await q.message.reply_text(
                "Am reținut. La mesajele următoare de la această persoană verific doar semnele "
                "cele mai grave (bani, coduri, acces la telefon). Reținerea se șterge când opresc botul.")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(on_know, pattern=r"^know:"))
    app.add_handler(MessageHandler(filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION)
                                   & ~filters.COMMAND, on_message))
    print("Botul pornit. Apăsați Ctrl+C pentru oprire.")
    app.run_polling()


if __name__ == "__main__":
    main()
