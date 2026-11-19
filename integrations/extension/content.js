// 2nd Eye - AlgoR3IthM: WhatsApp Web guard (content script).
// Also used unchanged by demo.html. Message text is only forwarded to the
// local API through the background worker; never stored, never logged.
(function () {
  "use strict";

  // ---- All DOM selectors live here (WhatsApp changes its DOM often) ----
  const SEL = {
    chat: ["#main", "[data-testid='conversation-panel-wrapper']", "div[role='application']"],
    header: ["#main header", "header[data-testid='conversation-header']", "[data-testid='conversation-header']", "header"],
    headerTitle: ["header span[title]", "header [data-testid='conversation-info-header-chat-title']", "header span[dir='auto']"],
    row: ["div[data-id]", "[data-testid='msg-container']", "div.message-in, div.message-out"],
    incoming: [".message-in", "[data-id^='false_']"],
    outgoing: [".message-out", "[data-id^='true_']"],
    text: ["span.selectable-text", "[data-testid='msg-text']", "span[dir='ltr']", "span.copyable-text"],
  };
  const PHONE_RE = /^\+?[\d\s().\-]{7,}$/;
  const DEBOUNCE_MS = 800;
  const MAX_MSGS = 30;

  const VERDICTS = {
    SAFE: { cls: "sb-safe", icon: "✔", label: "Pare în regulă" },
    SUSPICIOUS: { cls: "sb-warn", icon: "⚠", label: "Atenție, verificați înainte să răspundeți" },
    SCAM: { cls: "sb-scam", icon: "✖", label: "Pare o țeapă! Nu răspundeți" },
  };

  // ---- helpers ----
  const q1 = (list, root) => {
    for (const s of list) { try { const e = (root || document).querySelector(s); if (e) return e; } catch (_) {} }
    return null;
  };
  const qAll = (list, root) => {
    for (const s of list) { try { const e = (root || document).querySelectorAll(s); if (e.length) return Array.from(e); } catch (_) {} }
    return [];
  };
  const matches = (el, list) => list.some((s) => { try { return el.matches(s) || !!el.querySelector(s); } catch (_) { return false; } });

  function readChat() {
    const chat = q1(SEL.chat);
    if (!chat) return null;
    const header = q1(SEL.header, chat);
    const titleEl = header && q1(SEL.headerTitle, header);
    const title = ((titleEl && (titleEl.getAttribute("title") || titleEl.textContent)) || "").trim();
    if (!title) return null;
    const rows = qAll(SEL.row, chat).slice(-MAX_MSGS);
    const messages = [], els = [];
    for (const row of rows) {
      const parts = qAll(SEL.text, row).map((e) => e.textContent.trim()).filter(Boolean);
      const text = parts.join(" ").trim();
      if (!text) continue;
      const outgoing = matches(row, SEL.outgoing) && !matches(row, SEL.incoming);
      messages.push({ n: messages.length + 1, from: outgoing ? "reader" : "sender", text });
      els.push(row);
    }
    if (!messages.length) return null;
    const isNumber = PHONE_RE.test(title);
    return { chat, title, isNumber, messages, els };
  }

  // ---- UI (textContent only) ----
  function clearUi(chat) {
    chat.querySelectorAll(".sb-banner,.sb-tick").forEach((e) => e.remove());
    chat.querySelectorAll(".sb-first-alert").forEach((e) => e.classList.remove("sb-first-alert"));
  }

  function mk(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  function show(state, res, onDismiss) {
    const { chat, els } = state;
    clearUi(chat);
    const v = VERDICTS[res.verdict] || VERDICTS.SUSPICIOUS;
    if (res.verdict === "SAFE") {
      chat.appendChild(mk("div", "sb-tick", "✔"));
      chat.lastChild.title = "2nd Eye: pare în regulă";
      return;
    }
    const banner = mk("div", "sb-banner " + v.cls);
    banner.setAttribute("role", "alert");
    banner.appendChild(mk("div", "sb-icon", v.icon));
    const body = mk("div", "sb-body");
    body.appendChild(mk("div", "sb-title", v.label));
    body.appendChild(mk("div", "sb-text", (res.warning && res.warning.ro) || ""));
    banner.appendChild(body);
    const btn = mk("button", "sb-dismiss", "Am înțeles");
    btn.type = "button";
    btn.addEventListener("click", () => { banner.remove(); onDismiss(); });
    banner.appendChild(btn);
    chat.insertBefore(banner, chat.firstChild);
    const fa = res.first_alert;
    if (fa && els[fa - 1]) els[fa - 1].classList.add("sb-first-alert");
  }

  // ---- transport: background worker in the extension, direct fetch in demo ----
  function send(scenario, trustGate) {
    return new Promise((resolve) => {
      try {
        if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
          chrome.runtime.sendMessage({ type: "analyze", scenario, trustGate }, (r) => {
            void chrome.runtime.lastError;
            resolve(r && r.ok ? r.data : null);
          });
          return;
        }
      } catch (_) {}
      const base = (window.SB_API || "http://localhost:8000");
      fetch(base + "/api/analyze" + (trustGate ? "?trust_gate=true" : ""), {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(scenario),
      }).then((r) => (r.ok ? r.json() : null)).then(resolve).catch(() => resolve(null));
    });
  }

  // ---- main loop ----
  let lastSig = "", dismissedSig = "", busy = false, timer = null;

  async function check() {
    timer = null;
    if (busy) { schedule(); return; }
    let state;
    try { state = readChat(); } catch (_) { return; }
    if (!state) return;
    const sig = state.title + "\u0001" + state.messages.map((m) => m.from[0] + m.text).join("\u0002");
    if (sig === lastSig) return; // message list did not really change
    lastSig = sig;
    const known = !state.isNumber;
    const scenario = {
      id: "whatsapp-web",
      channel: "whatsapp",
      sender: { name: known ? state.title : null, address: known ? null : state.title, known_contact: known },
      messages: state.messages,
    };
    busy = true;
    try {
      const res = await send(scenario, known);
      if (!res || sig === dismissedSig) return;
      // the DOM may have been re-rendered meanwhile: re-read element references
      const fresh = readChat();
      show(fresh && fresh.title === state.title ? fresh : state, res, () => { dismissedSig = sig; });
    } catch (_) {
      /* fail silently */
    } finally { busy = false; }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(check, DEBOUNCE_MS);
  }

  function start() {
    const obs = new MutationObserver((muts) => {
      for (const m of muts) {
        const t = m.target.nodeType === 1 ? m.target : m.target.parentElement;
        if (t && t.closest && t.closest(".sb-banner,.sb-tick")) continue; // our own UI
        schedule();
        return;
      }
    });
    obs.observe(document.body, { childList: true, subtree: true, characterData: true });
    schedule();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
