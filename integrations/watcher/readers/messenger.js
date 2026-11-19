// @service messenger https://www.messenger.com/
// Messenger reader (messenger.com and facebook.com/messages). Unverified on a live account.
// Messenger has no in/out class: direction comes from left/right alignment of each message.
(function () {
  "use strict";
  if (!window.__SB) return;
  const SB = window.__SB, h = SB.h;

  const SEL = {
    main: ["div[role='main']", "main"],
    grid: ["div[role='grid'][aria-label]", "div[role='grid']"],
    row: ["div[role='row']"],
    text: ["div[dir='auto']", "span[dir='auto']"],
    titleFromLabel: /(?:titled|intitulat[ăa]?)\s+(.+)$/i,   // aria-label "Messages in conversation titled X"
    titleFallback: ["div[role='main'] h2 span", "div[role='main'] h1 span", "div[role='main'] a[role='link'] span[dir='auto']"],
    requestPath: /requests|message_requests|filtered|spam/i,
    acceptBtn: /^\s*(accept|acceptă|accepta)\s*$/i,
  };

  function scan() {
    if (/(^|\.)facebook\.com$/.test(location.hostname) && location.pathname.indexOf("/messages") !== 0) return null;
    const main = h.q1(SEL.main);
    if (!main) return null;
    const grid = h.q1(SEL.grid, main);
    let title = "";
    if (grid) { const m = (grid.getAttribute("aria-label") || "").match(SEL.titleFromLabel); if (m) title = m[1].trim(); }
    if (!title) title = h.text(h.q1(SEL.titleFallback));
    const rows = [];
    if (grid) {
      for (const row of h.qAll(SEL.row, grid)) {
        const blocks = h.qAll(SEL.text, row).filter((e) => !e.querySelector(SEL.text[0]));
        const text = blocks.map((e) => h.text(e)).filter(Boolean).join(" ").trim();
        if (!text) continue;
        rows.push({ from: h.side(blocks[0] || row, grid) || "sender", text, el: blocks[0] || row });
      }
    }
    // a conversation under message requests is a stranger
    let stranger = SEL.requestPath.test(h.pathHash());
    if (!stranger) {
      for (const b of main.querySelectorAll("button,[role='button']")) { if (SEL.acceptBtn.test(b.textContent || "")) { stranger = true; break; } }
    }
    return { header: !!title, sender: { name: title || null, address: null }, known_contact: !stranger, rows };
  }

  // thread list (best effort, markup is obfuscated): links to /t/ID; unread = unread label or bold preview.
  // Threads under message requests (href contains "requests") are strangers.
  const LIST = {
    item: ["div[role='navigation'] a[href*='/t/']", "div[aria-label='Chats'] a[href*='/t/']", "a[role='link'][href*='/t/']"],
    spans: "span[dir='auto'], span",
  };

  function list() {
    if (/(^|\.)facebook\.com$/.test(location.hostname) && location.pathname.indexOf("/messages") !== 0) return [];
    const out = [];
    for (const a of h.qAll(LIST.item)) {
      const spans = Array.from(a.querySelectorAll(LIST.spans)).filter((e) => !e.querySelector("span") && h.text(e));
      if (spans.length < 2) continue;
      const name = h.text(spans[0]);
      const pEl = spans[1];
      const href = a.getAttribute("href") || "";
      out.push({ name, address: null, stranger: SEL.requestPath.test(href), preview: h.text(pEl),
                 unread: h.hasUnread(a) || h.isBold(pEl), el: a });
    }
    return out;
  }

  SB.register({ name: "messenger", channel: "chat", hostnames: ["messenger.com", "facebook.com"], scan, list });
})();
