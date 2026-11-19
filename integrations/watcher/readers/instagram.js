// @service instagram https://www.instagram.com/direct/inbox/
// Instagram direct reader. Unverified on a live account; direction = left/right alignment.
(function () {
  "use strict";
  if (!window.__SB) return;
  const SB = window.__SB, h = SB.h;

  const SEL = {
    main: ["div[role='main']", "main"],
    row: ["div[role='row']", "div[role='listitem']"],
    text: ["div[dir='auto']", "span[dir='auto']"],
    title: ["div[role='main'] header h2", "div[role='main'] header a span", "div[role='main'] header span[dir='auto']",
            "div[role='main'] h2", "header span[title]"],
    requestPath: /\/direct\/requests|\/direct\/pending/i,
    acceptBtn: /^\s*(accept|acceptă|accepta)\s*$/i,
    threadPath: /\/direct\/(t|requests)\//i,
  };

  function scan() {
    if (!SEL.threadPath.test(h.pathHash())) return null;   // inbox list, not a conversation
    const main = h.q1(SEL.main);
    if (!main) return null;
    const title = h.text(h.q1(SEL.title));
    const rows = [];
    for (const row of h.qAll(SEL.row, main)) {
      const blocks = h.qAll(SEL.text, row).filter((e) => !e.querySelector(SEL.text[0]));
      const text = blocks.map((e) => h.text(e)).filter(Boolean).join(" ").trim();
      if (!text) continue;
      rows.push({ from: h.side(blocks[0] || row, main) || "sender", text, el: blocks[0] || row });
    }
    // conversations under message requests (or with an Accept button) come from people the person does not follow
    let stranger = SEL.requestPath.test(h.pathHash());
    if (!stranger) {
      for (const b of main.querySelectorAll("button,[role='button']")) { if (SEL.acceptBtn.test(b.textContent || "")) { stranger = true; break; } }
    }
    return { header: !!title, sender: { name: title || null, address: null }, known_contact: !stranger, rows };
  }

  // thread list (best effort): links to /direct/t/ID or /direct/requests/...; unread = unread label or bold preview.
  const LIST = {
    item: ["a[href*='/direct/t/'], a[href*='/direct/requests/']", "div[role='listbox'] a[role='link']", "div[role='button'][tabindex='0']"],
    spans: "span[dir='auto'], span",
  };

  function list() {
    if (location.pathname.indexOf("/direct") !== 0 && !/#\/direct/.test(location.hash)) return [];
    const out = [];
    for (const a of h.qAll(LIST.item)) {
      const spans = Array.from(a.querySelectorAll(LIST.spans)).filter((e) => !e.querySelector("span") && h.text(e));
      if (spans.length < 2) continue;
      const href = a.getAttribute("href") || "";
      out.push({ name: h.text(spans[0]), address: null, stranger: SEL.requestPath.test(href),
                 preview: h.text(spans[1]), unread: h.hasUnread(a) || h.isBold(spans[1]), el: a });
    }
    return out;
  }

  SB.register({ name: "instagram", channel: "chat", hostnames: ["instagram.com"], scan, list });
})();
