// 2nd Eye - AlgoR3IthM: shared watcher code (injected before every reader).
// Registry, debounced observer, content hash, warning banner, Ctrl+Shift+S diagnostic.
// Privacy: message text is only passed to the Python binding (local API). Never logged or stored.
// CSP / Trusted Types safe: no innerHTML, no inline <style>, no fetch; all DOM via createElement + textContent.
(function () {
  "use strict";
  if (window.top !== window || window.__SB) return;

  const DEBOUNCE_MS = 700;
  const RETRY_MS = 15000;
  const MAX_MSGS = 30;
  const MAX_TEXT = 2000;
  const ROOT_ID = "sb-root";
  // set by watcher.py before this script: banner (draw in page), list (poll chat/inbox list), openStrangers, pollMs
  const CFG = Object.assign({ banner: true, list: false, openStrangers: false, pollMs: 20000 }, window.__SB_CFG || {});

  const VERDICTS = {
    SAFE: { icon: "✔", label: "Pare în regulă", bg: "#2e7d32", fg: "#ffffff" },
    SUSPICIOUS: { icon: "⚠", label: "Atenție, verificați înainte să răspundeți", bg: "#ffb300", fg: "#1a1a1a" },
    SCAM: { icon: "✖", label: "Pare o țeapă! Nu răspundeți", bg: "#b71c1c", fg: "#ffffff" },
  };

  // ---------------------------------------------------------------- helpers for readers
  const h = {
    q1(list, root) {
      for (const s of [].concat(list)) { try { const e = (root || document).querySelector(s); if (e) return e; } catch (_) {} }
      return null;
    },
    qAll(list, root) {
      for (const s of [].concat(list)) {
        try { const e = (root || document).querySelectorAll(s); if (e.length) return Array.from(e); } catch (_) {}
      }
      return [];
    },
    text(el) { return ((el && el.textContent) || "").replace(/\s+/g, " ").trim(); },
    // text of an element with some descendants removed (time stamps, quotes, ...)
    textWithout(el, dropSelectors) {
      if (!el) return "";
      const c = el.cloneNode(true);
      for (const s of [].concat(dropSelectors || [])) { try { c.querySelectorAll(s).forEach((n) => n.remove()); } catch (_) {} }
      return h.text(c);
    },
    // unread marker inside a list row: aria-label / class says "unread", or the caller's extra selector matches
    hasUnread(row, extraSel) {
      try {
        if (extraSel && row.querySelector(extraSel)) return true;
        if (row.querySelector("[aria-label*='unread' i],[aria-label*='necitit' i],[class*='unread' i]")) return true;
      } catch (_) {}
      return false;
    },
    isBold(el) {
      try { return parseInt(getComputedStyle(el).fontWeight, 10) >= 600; } catch (_) { return false; }
    },
    isPhone(s) { return /^\+?[\d\s().\-]{7,}$/.test((s || "").trim()); },
    // message bubble on the left half of the container = incoming, right half = outgoing
    side(el, container) {
      try {
        const r = el.getBoundingClientRect(), c = (container || document.body).getBoundingClientRect();
        if (!r.width || !c.width) return null;
        return (r.left + r.width / 2) < (c.left + c.width / 2) ? "sender" : "reader";
      } catch (_) { return null; }
    },
    // does any button / link on the page match this regexp (labels only, no message text)
    hasControl(re, root) {
      const nodes = (root || document).querySelectorAll("button,[role='button'],a[role='link']");
      for (const n of nodes) { if (re.test((n.textContent || "") + " " + (n.getAttribute("aria-label") || ""))) return true; }
      return false;
    },
    pathHash() { return location.pathname + location.hash; },
  };

  // ---------------------------------------------------------------- registry
  // Reader contract: SB.register({ name, channel, hostnames:[...], scan(), list() })
  // list() reads the chat / inbox list WITHOUT clicking: array of
  //   { name, address, stranger: bool, preview: "text the list shows", unread: bool, el }
  // scan() returns null (no conversation open) or
  //   { header: bool, sender:{name,address}, known_contact: bool,
  //     rows: [{ from:"sender"|"reader", text, el? }] }
  const readers = [];
  const SB = { h, readers, register(r) { if (r && r.name && typeof r.scan === "function") readers.push(r); } };
  window.__SB = SB;

  function activeReader() {
    const host = location.hostname;
    const local = host === "localhost" || host === "127.0.0.1";
    const demo = local && document.querySelector("meta[name='sb-demo']");
    for (const r of readers) {
      if (demo && demo.content === r.name) return r;
      if (!demo && (r.hostnames || []).some((x) => host === x || host.endsWith("." + x))) {
        if (!r.pathPrefixes || r.pathPrefixes.some((p) => location.pathname.indexOf(p) === 0)) return r;
      }
    }
    return null;
  }

  // read the open conversation; never throws
  function readConv(r) {
    let raw = null;
    try { raw = r.scan(); } catch (_) { raw = null; }
    if (!raw) return { conv: null, diag: { header: false, total: 0, incoming: 0, outgoing: 0, known: null } };
    const rows = (raw.rows || []).filter((x) => x && x.text && x.text.trim()).slice(-MAX_MSGS);
    const diag = {
      header: !!raw.header, total: rows.length,
      incoming: rows.filter((x) => x.from === "sender").length,
      outgoing: rows.filter((x) => x.from === "reader").length,
      known: !!raw.known_contact,
    };
    const sender = raw.sender || {};
    if (!rows.length || !(sender.name || sender.address)) return { conv: null, diag };
    const conv = {
      service: r.name, channel: r.channel || "chat",
      sender: { name: sender.name || null, address: sender.address || null },
      known_contact: !!raw.known_contact,
      messages: rows.map((x, i) => ({ n: i + 1, from: x.from === "reader" ? "reader" : "sender", text: x.text.slice(0, MAX_TEXT) })),
      elements: rows.map((x) => x.el || null),
    };
    return { conv, diag };
  }

  // ---------------------------------------------------------------- content hash (in memory only)
  function hashConv(c) {
    let hh = 0x811c9dc5, len = 0;
    const feed = (s) => { for (let i = 0; i < s.length; i++) { hh ^= s.charCodeAt(i); hh = Math.imul(hh, 0x01000193) >>> 0; } len += s.length; };
    feed(c.service); feed("|" + (c.sender.address || "") + "|" + (c.sender.name || "") + "|" + c.known_contact + "|");
    for (const m of c.messages) feed(m.from[0] + m.text + "\u0001");
    return hh.toString(16) + ":" + len + ":" + c.messages.length;
  }

  // ---------------------------------------------------------------- UI
  function mk(tag, text, style) {
    const e = document.createElement(tag);
    if (text) e.textContent = text;
    if (style) Object.assign(e.style, style);
    return e;
  }
  const BASE = { fontFamily: "Segoe UI, Arial, sans-serif", boxSizing: "border-box", lineHeight: "1.35", margin: "0" };

  function root() {
    let r = document.getElementById(ROOT_ID);
    if (!r || !r.isConnected) {
      r = document.createElement("div");
      r.id = ROOT_ID;
      Object.assign(r.style, { position: "fixed", top: "0", left: "0", right: "0", zIndex: "2147483647", pointerEvents: "none" });
      (document.body || document.documentElement).appendChild(r);
    }
    return r;
  }

  let outlined = null;
  function clearUi() {
    const r = document.getElementById(ROOT_ID);
    if (r) while (r.firstChild) r.removeChild(r.firstChild);
    if (outlined) { try { outlined.style.outline = ""; outlined.style.outlineOffset = ""; } catch (_) {} outlined = null; }
  }

  function button(label, bg, fg, onClick) {
    const b = mk("button", label, Object.assign({}, BASE, {
      fontSize: "20px", fontWeight: "600", padding: "10px 18px", border: "2px solid " + fg, borderRadius: "8px",
      background: bg, color: fg, cursor: "pointer", minHeight: "48px",
    }));
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function showResult(st, conv, out) {
    clearUi();
    const res = out.result || {};
    const v = VERDICTS[res.verdict] || VERDICTS.SUSPICIOUS;
    const r = root();
    if (res.verdict === "SAFE") {
      const t = mk("div", v.icon, Object.assign({}, BASE, {
        position: "absolute", top: "8px", right: "16px", width: "30px", height: "30px", borderRadius: "50%",
        background: v.bg, color: v.fg, fontSize: "18px", textAlign: "center", lineHeight: "30px", opacity: "0.85",
        pointerEvents: "auto",
      }));
      t.title = "2nd Eye: " + v.label;
      r.appendChild(t);
      return;
    }
    const banner = mk("div", "", Object.assign({}, BASE, {
      pointerEvents: "auto", display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap",
      margin: "0 auto", maxWidth: "980px", padding: "14px 20px", background: v.bg, color: v.fg,
      border: "4px solid " + v.fg, borderTop: "0", borderRadius: "0 0 14px 14px", boxShadow: "0 6px 24px rgba(0,0,0,.45)",
    }));
    banner.setAttribute("role", "alert");
    banner.appendChild(mk("div", v.icon, Object.assign({}, BASE, { fontSize: "44px", fontWeight: "700" })));
    const body = mk("div", "", Object.assign({}, BASE, { flex: "1 1 320px" }));
    body.appendChild(mk("div", v.label, Object.assign({}, BASE, { fontSize: "26px", fontWeight: "800" })));
    // only the API's warning text is shown: never links or numbers from the conversation
    body.appendChild(mk("div", (res.warning && res.warning.ro) || "", Object.assign({}, BASE, { fontSize: "22px", marginTop: "6px" })));
    banner.appendChild(body);
    const btns = mk("div", "", Object.assign({}, BASE, { display: "flex", gap: "10px", flexWrap: "wrap" }));
    btns.appendChild(button("Am înțeles", "transparent", v.fg, () => { st.dismissed = st.hash; st.lastHadUi = false; clearUi(); }));
    if (!out.known) {
      btns.appendChild(button("Îl cunosc", "transparent", v.fg, () => {
        clearUi();
        call("__sbTrust", { service: conv.service, sender: conv.sender }).then(() => { st.hash = ""; st.dismissed = ""; schedule(0); });
      }));
    }
    banner.appendChild(btns);
    r.appendChild(banner);
    const fa = res.first_alert;
    const el = fa && conv.elements[fa - 1];
    if (el && el.isConnected) {
      el.style.outline = "4px solid " + (res.verdict === "SCAM" ? "#b71c1c" : "#ffb300");
      el.style.outlineOffset = "3px";
      outlined = el;
    }
  }

  // ---------------------------------------------------------------- Ctrl+Shift+S diagnostic (counts only)
  function showDiag() {
    const old = document.getElementById("sb-diag");
    if (old) { old.remove(); return; }
    const r = activeReader();
    const box = mk("div", "", Object.assign({}, BASE, {
      position: "fixed", bottom: "16px", left: "16px", zIndex: "2147483647", background: "#111", color: "#fff",
      padding: "12px 16px", borderRadius: "10px", fontSize: "16px", border: "2px solid #888", whiteSpace: "pre",
    }));
    box.id = "sb-diag";
    if (!r) {
      box.textContent = "2nd Eye\nniciun cititor pentru această pagină";
    } else {
      const d = readConv(r).diag;
      const ld = { rows: 0, unread: 0, strangers: 0 };
      try { const L = (r.list && r.list()) || []; ld.rows = L.length; ld.unread = L.filter((x) => x.unread).length; ld.strangers = L.filter((x) => x.unread && x.stranger).length; } catch (_) {}
      box.textContent = "2nd Eye - diagnostic (" + r.name + ")\n" +
        "header gasit: " + (d.header ? "da" : "nu") + "\n" +
        "mesaje gasite: " + d.total + "\n" +
        "primite: " + d.incoming + "   trimise: " + d.outgoing + "\n" +
        "contact: " + (d.known === null ? "-" : d.known ? "cunoscut" : "necunoscut") + "\n" +
        "lista: " + ld.rows + " randuri, " + ld.unread + " necitite, " + ld.strangers + " necunoscuti\n" +
        "(Ctrl+Shift+S pentru a inchide)";
    }
    (document.body || document.documentElement).appendChild(box);
    setTimeout(() => { try { box.remove(); } catch (_) {} }, 15000);
  }

  // ---------------------------------------------------------------- counts-only self-check for watcher.py --diag
  // Returns booleans and numbers only (plus error NAME and script line). Never any page text.
  function errInfo(e) {
    const m = String((e && e.stack) || "").match(/:(\d+):\d+/);
    return ((e && e.name) || "Error") + (m ? "@" + m[1] : "");
  }
  SB.diag = function () {
    const out = { sb: true, reader: null, errors: [], header: false, msgs: 0, incoming: 0, outgoing: 0, known: null,
                  rows: 0, unread: 0, strangers: 0, listOk: false, scanOk: false,
                  overlay: !!document.getElementById("sb-diag"), booted: !!SB.booted };
    let r = null;
    try { r = activeReader(); } catch (e) { out.errors.push("activeReader:" + errInfo(e)); }
    if (!r) return out;
    out.reader = r.name;
    try {
      const raw = r.scan();
      out.scanOk = true;
      if (raw) {
        const rows = (raw.rows || []).filter((x) => x && x.text && x.text.trim());
        out.header = !!raw.header; out.msgs = rows.length;
        out.incoming = rows.filter((x) => x.from === "sender").length;
        out.outgoing = rows.filter((x) => x.from === "reader").length;
        out.known = !!raw.known_contact;
      }
    } catch (e) { out.errors.push("scan:" + errInfo(e)); }
    try {
      const L = (r.list && r.list()) || [];
      out.listOk = true; out.rows = L.length;
      out.unread = L.filter((x) => x.unread).length;
      out.strangers = L.filter((x) => x.unread && x.stranger).length;
      out.wa = SB.waStats || null;   // WhatsApp only: all list rows seen, before the unknown-number filter
    } catch (e) { out.errors.push("list:" + errInfo(e)); }
    return out;
  };
  // click the first list row that has no unread marker (never an unread one: opening marks it read). Returns a boolean.
  SB.openRead = function (skip) {
    const r = activeReader();
    if (!r || !r.list) return false;
    const L = r.list() || [];
    const rows = L.filter((x) => !x.unread && x.el);
    const it = rows[Math.min(skip || 0, rows.length - 1)];
    if (!it) return null;
    it.el.scrollIntoView({ block: "center" });
    const b = it.el.getBoundingClientRect();
    return [Math.round(b.left + b.width / 2), Math.round(b.top + b.height / 2)];   // caller does a real mouse click
  };
  // redacted structural skeleton of the first element matching sel (tags, roles, attribute NAMES, class names, counts, text lengths)
  SB.skeleton = function (sel, maxDepth, maxKids) {
    const SAFE_VAL = /^(aria-hidden|aria-selected|aria-expanded|dir)$/;
    const FIXED = /^(data-testid|data-icon|data-id|data-tab)$/;
    const red = (v) => String(v).replace(/\S*@\S*/g, "#").replace(/[A-Za-z0-9]*\d[A-Za-z0-9]*/g, (t) => (t.length >= 5 ? "#" : t)).replace(/[A-Fa-f0-9]{8,}/g, "#").slice(0, 60);
    const walk = (el, d) => {
      const bits = [el.tagName.toLowerCase()];
      const role = el.getAttribute("role"); if (role) bits.push("role=" + role.slice(0, 20));
      for (const a of Array.from(el.attributes)) {
        const n = a.name;
        if (n === "class" || n === "role") continue;
        if (SAFE_VAL.test(n)) bits.push(n + "=" + a.value.slice(0, 10));
        else if (FIXED.test(n)) bits.push(n + "=" + (n === "data-id" ? (/^(true|false)_/.test(a.value) ? a.value.split("_")[0] + "_#" : "#") : red(a.value)));
        else if (/^(data|aria)-/.test(n)) bits.push(n);
      }
      const cls = (typeof el.className === "string" ? el.className : "").trim().split(/\s+/).filter(Boolean).slice(0, 4);
      if (cls.length) bits.push("." + cls.map((c) => c.slice(0, 24)).join("."));
      let own = 0; for (const n of el.childNodes) if (n.nodeType === 3) own += n.textContent.trim().length;
      if (own) bits.push("txt" + own);
      const kids = Array.from(el.children);
      let s = "  ".repeat(d) + bits.join(" ") + (kids.length ? " [" + kids.length + "]" : "") + "\n";
      if (d < maxDepth) for (const k of kids.slice(0, maxKids)) s += walk(k, d + 1);
      return s;
    };
    const e = document.querySelector(sel);
    return e ? walk(e, 0) : "(no match)\n";
  };

  // ---------------------------------------------------------------- bindings (Python does the HTTP)
  function call(name, arg) {
    try { if (typeof window[name] === "function") return Promise.resolve(window[name](arg)).catch(() => null); } catch (_) {}
    return Promise.resolve(null);
  }
  SB.call = call;   // readers use it for host input (__sbInput) and counts-only notes (__sbNote)

  // ---------------------------------------------------------------- main loop
  const st = { hash: "", failedHash: "", last: null, dismissed: "", busy: false, timer: null, retryAt: 0, reader: null, lastHadUi: false };

  async function check() {
    st.timer = null;
    if (st.busy) { schedule(DEBOUNCE_MS); return; }
    const r = st.reader || (st.reader = activeReader());
    if (!r) return;
    const { conv } = readConv(r);
    if (!conv) { if (st.hash) { st.hash = ""; clearUi(); } return; }
    const hash = hashConv(conv);
    if (hash === st.hash) {                           // same conversation state: never analyse twice
      const rt = document.getElementById(ROOT_ID);
      if (CFG.banner && st.last && st.lastHadUi && !(rt && rt.firstChild)) showResult(st, conv, st.last);   // site wiped our UI
      return;
    }
    if (hash === st.failedHash && Date.now() < st.retryAt) return;
    st.busy = true;
    try {
      const out = await call("__sbAnalyze", { source: "conv", service: conv.service, scenario: scenarioOf(conv) });
      if (!out || !out.ok) { st.failedHash = hash; st.retryAt = Date.now() + RETRY_MS; setTimeout(() => schedule(0), RETRY_MS + 50); return; }
      st.hash = hash; st.last = out; st.failedHash = "";
      const fresh = readConv(r).conv;                  // DOM may have been re-rendered meanwhile
      const c2 = fresh && hashConv(fresh) === hash ? fresh : conv;
      if (!CFG.banner || st.dismissed === hash) { clearUi(); st.lastHadUi = false; return; }
      showResult(st, c2, out);
      st.lastHadUi = true;
    } catch (_) { /* fail silently */ } finally { st.busy = false; }
  }

  // ---------------------------------------------------------------- list path (nothing is opened or clicked by default)
  const seen = new Set();
  function fnv(str) {
    let x = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) { x ^= str.charCodeAt(i); x = Math.imul(x, 0x01000193) >>> 0; }
    return x.toString(16) + ":" + str.length;
  }
  let listBusy = false, listTimer = null;
  async function pollList() {
    listTimer = null;
    const r = st.reader || (st.reader = activeReader());
    if (!r || typeof r.list !== "function" || listBusy) return;
    let items = [];
    try { items = r.list() || []; } catch (_) { return; }
    listBusy = true;
    try {
      let opened = false;
      for (const it of items) {
        // "always" rows (WhatsApp unknown numbers) are checked whether or not they are unread
        if (!it || !(it.unread || it.always) || !(it.name || it.address)) continue;
        const text = (it.preview || "").replace(/\s+/g, " ").trim().slice(0, MAX_TEXT);
        const opens = !!(it.open && typeof r.openAndRead === "function" && it.key);
        if (!text && !opens) continue;                    // threads that are opened are read even if she wrote last
        const hk = fnv(r.name + "|" + (it.address || "") + "|" + (it.name || "") + "|" + (opens ? it.key : text));
        if (seen.has(hk)) continue;                       // same preview: never analysed twice
        // Readers that open a row to read the whole thread (WhatsApp unknown numbers) do it here, one at a time.
        if (it.open && typeof r.openAndRead === "function") {
          let conv = null;
          try { conv = await r.openAndRead(it); } catch (_) { conv = null; }
          const rows = conv && conv.rows && conv.rows.length ? conv.rows.slice(-MAX_MSGS) : (text ? [{ from: "sender", text }] : []);
          if (!rows.length) {                             // nothing readable from the other person: no analysis
            try { if (typeof r.afterRead === "function") await r.afterRead(it, null, conv); } catch (_) {}
            seen.add(hk);
            continue;
          }
          const res = await call("__sbAnalyze", { source: "list", service: r.name, scenario: {
            channel: r.channel || "chat",
            sender: { name: null, address: it.address || null, known_contact: false },
            known_contact: false,
            messages: rows.map((m, i) => ({ n: i + 1, from: m.from === "reader" ? "reader" : "sender", text: String(m.text).slice(0, MAX_TEXT) })),
          } });
          const verdict = res && res.ok && res.result ? res.result.verdict : null;
          try { if (typeof r.afterRead === "function") await r.afterRead(it, verdict, conv); } catch (_) {}
          if (res && res.ok) seen.add(hk);
          continue;
        }
        const known = !it.stranger;
        const out = await call("__sbAnalyze", { source: "list", service: r.name, scenario: {
          channel: r.channel || "chat",
          sender: { name: it.name || null, address: it.address || null, known_contact: known },
          known_contact: known,
          messages: [{ n: 1, from: "sender", text }],
        } });
        if (!out || !out.ok) continue;                    // API down: retried on the next poll
        seen.add(hk);
        // opt-in only: opening an unread chat marks it as read on the phone
        if (CFG.openStrangers && it.stranger && !out.known && it.el && !opened) { opened = true; try { it.el.click(); } catch (_) {} }
      }
    } catch (_) { /* fail silently */ } finally { listBusy = false; }
  }
  function scheduleList(ms) {
    if (!CFG.list) return;
    clearTimeout(listTimer);
    listTimer = setTimeout(pollList, ms === undefined ? 500 : ms);
  }

  function scenarioOf(c) {
    return {
      channel: c.channel,
      sender: { name: c.sender.name, address: c.sender.address, known_contact: c.known_contact },
      known_contact: c.known_contact,
      messages: c.messages,
    };
  }

  function schedule(ms) {
    clearTimeout(st.timer);
    st.timer = setTimeout(check, ms === undefined ? DEBOUNCE_MS : ms);
  }

  function boot() {
    if (!activeReader()) return;
    SB.booted = true;
    const obs = new MutationObserver((muts) => {
      for (const m of muts) {
        const t = m.target.nodeType === 1 ? m.target : m.target.parentElement;
        if (t && t.closest && t.closest("#" + ROOT_ID + ",#sb-diag")) continue;   // our own UI
        schedule();
        scheduleList();
        return;
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
    window.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.shiftKey && (e.key === "S" || e.key === "s")) { e.preventDefault(); showDiag(); }
    }, true);
    window.addEventListener("hashchange", () => schedule(200));
    schedule(1500);
    if (CFG.list) { scheduleList(3000); setInterval(() => scheduleList(0), CFG.pollMs); }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
