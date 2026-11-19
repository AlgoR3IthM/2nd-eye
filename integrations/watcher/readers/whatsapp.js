// @service whatsapp https://web.whatsapp.com/
// WhatsApp Web reader.
// Team rules:
//  1. Only chats whose title starts with "+" or a digit are touched: a number that is not saved in the
//     phone book. Saved contacts and groups (titles that are names) are never read.
//  2. Those chats are opened so the whole thread is analysed, not just the preview line.
//  3. If the verdict is SAFE and the chat was unread, it is marked as unread again, so she still sees it.
(function () {
  "use strict";
  if (!window.__SB) return;
  const SB = window.__SB, h = SB.h;

  // ---- every selector lives here, first match wins ----
  const SEL = {
    chat: ["#main", "[data-testid='conversation-panel-wrapper']"],
    header: ["#main header", "header[data-testid='conversation-header']", "[data-testid='conversation-header']", "header"],
    title: ["[data-testid='conversation-info-header-chat-title']", "span[title]", "span[dir='auto']"],
    row: ["div[data-id]", "[data-testid='msg-container']", "div.message-in, div.message-out", "div[role='row']"],
    incoming: [".message-in", "[data-id^='false_']", "[data-testid='msg-container'] > div.false", "[data-icon='tail-in']"],
    outgoing: [".message-out", "[data-id^='true_']", "[data-testid='msg-container'] > div.true", "[data-icon='tail-out']"],
    text: ["[data-testid='selectable-text']","span.selectable-text.copyable-text", "span.selectable-text", "[data-testid='msg-text']", "span.copyable-text"],
  };
  // chat list (left pane)
  const LIST = {
    pane: ["#pane-side", "[data-testid='chat-list']"],
    item: ["#pane-side [role='grid'] [role='row']", "div[role='listitem']","[data-testid='cell-frame-container']", "div[role='row']"],
    title: ["span[title][dir='auto']", "span[title]"],
    preview: ["[data-testid='last-msg'] span[dir]", "span[dir='ltr'][title]", "span[dir='ltr']"],
    unread: "[aria-label*='unread' i],[aria-label*='necitit' i],[data-testid='icon-unread-count']",
  };
  // context-menu entry, English and Romanian interface
  const MENU_UNREAD = /^(mark as unread|marcheaz[ăa] ca necitit[ăa]?)$/i;
  const MENU_ITEMS = "[role='application'] li, [role='menu'] [role='menuitem'], [role='menuitem'], li[role='button'], li";

  const is = (el, list) => list.some((s) => { try { return el.matches(s) || !!el.querySelector(s); } catch (_) { return false; } });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function unknownNumber(title) { return /^\s*[+\d]/.test(title || ""); }
  function titleOf(el) { return el ? (el.getAttribute("title") || h.text(el)) : ""; }

  // The in-page banner path is off for WhatsApp: chats are read through openAndRead() below.
  function scan() { return null; }

  function openTitle() {
    const chat = h.q1(SEL.chat);
    const header = chat && h.q1(SEL.header, chat);
    return titleOf(header && h.q1(SEL.title, header)).trim();
  }

  // Who wrote a message row. WhatsApp marks every message with data-id "true_..." when it was sent from
  // this account and "false_..." when it was received; that is checked first. Bubble classes and the
  // bubble tail icon are fallbacks. Returns "reader" (her own message), "sender" or null (unknown).
  const digits = (s) => String(s || "").replace(/\D/g, "");
  function direction(row, title, box, c) {
    // 1. WhatsApp's copy header on each text message: data-pre-plain-text="[14:05, 19.11.2026] <author>: ".
    //    In a chat with an unknown number the other person's author is that number; anyone else is her.
    const pre = row.querySelector && row.querySelector("[data-pre-plain-text]");
    const ph = pre && pre.getAttribute("data-pre-plain-text");
    if (ph && digits(title).length >= 6) {
      const m = /\]\s*(.*?):\s*$/.exec(ph);
      if (m && m[1]) {
        const same = digits(m[1]).length >= 6 && digits(m[1]).slice(-9) === digits(title).slice(-9);
        c.byAuthor++;
        return same ? "sender" : "reader";
      }
    }
    // 2. Bubble position: her messages sit on the right half of the conversation, the other person's on the left.
    const t = h.q1(SEL.text, row);
    if (t && box && box.width) {
      const r = t.getBoundingClientRect();
      if (r.width) { c.byPosition++; return (r.left + r.width / 2) > (box.left + box.width / 2) ? "reader" : "sender"; }
    }
    c.byOther++;
    const own = row.getAttribute && row.getAttribute("data-id");
    if (own && /^true_/.test(own)) return "reader";
    if (own && /^false_/.test(own)) return "sender";
    const inner = row.querySelector && row.querySelector("[data-id^='true_'],[data-id^='false_']");
    if (inner) return /^true_/.test(inner.getAttribute("data-id")) ? "reader" : "sender";
    const out = is(row, SEL.outgoing), inc = is(row, SEL.incoming);
    if (out && !inc) return "reader";
    if (inc && !out) return "sender";
    return null;
  }

  function readOpen() {
    const chat = h.q1(SEL.chat);
    if (!chat) return [];
    const rows = [];
    let unknown = 0;
    // counts only, to check the direction signals on a live account (no text, no ids)
    const c = { rows: 0, container: 0, noText: 0, idTrue: 0, idFalse: 0, idOther: 0, noId: 0,
                clsOut: 0, clsIn: 0, tailOut: 0, tailIn: 0, ticks: 0, byAuthor: 0, byPosition: 0, byOther: 0 };
    const title = openTitle();
    const box = chat.getBoundingClientRect();
    for (const row of h.qAll(SEL.row, chat)) {
      c.rows++;
      // skip containers that hold other message rows (their text would be counted twice)
      if (row.querySelector && row.querySelector("div[data-id]")) { c.container++; continue; }
      const text = h.qAll(SEL.text, row).map((e) => h.text(e)).filter(Boolean).join(" ").trim();
      if (!text) { c.noText++; continue; }
      const id = row.getAttribute("data-id");
      if (id == null) c.noId++; else if (/^true_/.test(id)) c.idTrue++; else if (/^false_/.test(id)) c.idFalse++; else c.idOther++;
      if (row.closest(".message-out") || row.querySelector(".message-out")) c.clsOut++;
      if (row.closest(".message-in") || row.querySelector(".message-in")) c.clsIn++;
      if (row.querySelector("[data-icon='tail-out']")) c.tailOut++;
      if (row.querySelector("[data-icon='tail-in']")) c.tailIn++;
      if (row.querySelector("[data-icon*='check'],[data-icon*='status-time'],[data-icon='msg-time']")) c.ticks++;
      const d = direction(row, title, box, c);
      if (!d) { unknown++; continue; }          // direction unknown: never guess "sender" for her own words
      rows.push({ from: d, text });
    }
    SB.waDir = { unknown, c };
    return rows;
  }

  function findRow(title) {
    for (const row of h.qAll(LIST.item, h.q1(LIST.pane) || document)) {
      if (titleOf(h.q1(LIST.title, row)) === title) return row;
    }
    return null;
  }

  // Real mouse / keyboard input through the host when it offers it (desktop watcher); synthetic events otherwise.
  async function hostInput(arg) { return SB.call ? !!(await SB.call("__sbInput", arg)) : false; }
  async function clickEl(el, button) {
    try { el.scrollIntoView({ block: "center" }); } catch (_) {}
    await sleep(150);
    const b = el.getBoundingClientRect();
    const x = b.left + Math.min(b.width / 2, 180), y = b.top + b.height / 2;
    if (await hostInput({ type: "click", x, y, button: button || "left" })) return;
    const o = { bubbles: true, cancelable: true, clientX: x, clientY: y, button: button === "right" ? 2 : 0 };
    if (button === "right") el.dispatchEvent(new MouseEvent("contextmenu", o));
    else for (const t of ["mousedown", "mouseup", "click"]) el.dispatchEvent(new MouseEvent(t, o));
  }
  async function pressEscape() {
    if (await hostInput({ type: "key", key: "Escape" })) return;
    const o = { key: "Escape", code: "Escape", keyCode: 27, which: 27, bubbles: true, cancelable: true };
    (document.activeElement || document.body).dispatchEvent(new KeyboardEvent("keydown", o));
  }

  // list(): only unknown numbers; every other row is skipped entirely
  function list() {
    const pane = h.q1(LIST.pane);
    if (!pane) return [];
    const out = [];
    const stats = { items: 0, titled: 0, withPreview: 0 };   // counts only, for --diag
    SB.waStats = stats;
    for (const row of h.qAll(LIST.item, pane)) {
      stats.items++;
      const title = titleOf(h.q1(LIST.title, row));
      const preview = titleOf(h.q1(LIST.preview, row));
      if (title) stats.titled++;
      if (title && preview) stats.withPreview++;
      if (!unknownNumber(title)) continue;
      // her own last message shows a delivery tick in front of the preview: that text is not from the stranger
      const mine = !!row.querySelector("[data-icon*='check'],[data-icon*='status-time'],[data-icon='msg-time']");
      // key: raw preview + who wrote it, so a new message from either side triggers one fresh read of the thread
      out.push({ name: null, address: title, stranger: true, preview: mine ? "" : preview, previewMine: mine, always: true, open: true,
                 key: (mine ? "her:" : "them:") + preview,
                 unread: h.hasUnread(row, LIST.unread), el: row });
    }
    return out;
  }

  // Open one unknown-number chat and return its messages. Called by common.js for rows with open:true.
  async function openAndRead(it) {
    const row = findRow(it.address);
    if (!row) return null;
    const conv = { rows: [], wasUnread: h.hasUnread(row, LIST.unread), clicked: true, opened: false };
    await clickEl(row);
    for (let i = 0; i < 25 && !conv.opened; i++) { await sleep(200); conv.opened = openTitle() === it.address; }
    if (conv.opened) { await sleep(900); conv.rows = readOpen(); }   // let the messages render
    return conv;
  }

  // Close the chat again (an open chat marks new messages as read), then restore the unread marker when
  // the thread was SAFE, or could not be analysed, and it had been unread before we opened it.
  async function afterRead(it, verdict, conv) {
    if (!conv || !conv.clicked) return;
    const note = { service: "whatsapp", opened: conv.opened, msgs: conv.rows.length, wasUnread: conv.wasUnread, closed: false, restored: false,
                   incoming: conv.rows.filter((m) => m.from === "sender").length,
                   outgoing: conv.rows.filter((m) => m.from === "reader").length,
                   unknownDir: (SB.waDir && SB.waDir.unknown) || 0,
                   dirCounts: (SB.waDir && SB.waDir.c) || null };
    await pressEscape();
    await sleep(500);
    note.closed = !h.q1(SEL.chat);
    if (conv.wasUnread && (verdict === "SAFE" || verdict === null)) note.restored = await markUnread(it.address);
    if (SB.call) SB.call("__sbNote", note);                      // counts and yes/no only
  }

  async function markUnread(title) {
    const row = findRow(title);
    if (!row) return false;
    await clickEl(row, "right");
    for (let i = 0; i < 12; i++) {
      await sleep(150);
      const hit = Array.from(document.querySelectorAll(MENU_ITEMS)).find((e) => MENU_UNREAD.test(h.text(e)));
      if (hit) { await clickEl(hit); await sleep(300); return true; }
    }
    await pressEscape();                                          // menu item not found: close the menu
    return false;
  }

  SB.register({ name: "whatsapp", channel: "whatsapp", hostnames: ["web.whatsapp.com"], scan, list, openAndRead, afterRead });
})();
