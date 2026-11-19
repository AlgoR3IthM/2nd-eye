// @service gmail https://mail.google.com/
// Gmail reader: the open thread. Unverified on a live account. Gmail enforces Trusted Types: only createElement/textContent are used.
(function () {
  "use strict";
  if (!window.__SB) return;
  const SB = window.__SB, h = SB.h;

  const SEL = {
    main: ["div[role='main']"],
    subject: ["h2.hP", "h2[data-thread-perm-id]"],
    message: ["div.adn", "div[data-message-id]"],
    sender: ["span.gD[email]", "h3 span[email]", "span[email]"],
    body: ["div.a3s.aiL", "div.a3s"],
    dropInBody: ["div.gmail_quote", "blockquote", "div.gmail_extra", "div.yj6qo", "div.adL"],
    account: ["a[aria-label*='@'][href*='SignOutOptions']", "a.gb_B[aria-label]", "a[aria-label^='Google Account']", "a[aria-label^='Cont Google']"],
    trustedMark: "img[alt*='trusted' i], span[aria-label*='trusted' i]",
  };

  function accountEmail() {
    const a = h.q1(SEL.account);
    const m = a && (a.getAttribute("aria-label") || "").match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
    return m ? m[0].toLowerCase() : "";
  }

  function scan() {
    const main = h.q1(SEL.main);
    if (!main) return null;
    const subject = h.q1(SEL.subject, main);
    const msgEls = h.qAll(SEL.message, main);
    if (!subject && !msgEls.length) return null;             // inbox list, not a thread
    const me = accountEmail();
    const rows = [];
    let from = null, outgoing = 0;
    for (const m of msgEls) {
      const bodyEl = h.q1(SEL.body, m);
      if (!bodyEl) continue;                                  // collapsed message: nothing to read
      const sEl = h.q1(SEL.sender, m);
      const addr = ((sEl && sEl.getAttribute("email")) || "").toLowerCase();
      const own = !!addr && !!me && addr === me;
      let text = h.textWithout(bodyEl, SEL.dropInBody);
      if (subject && rows.length === 0) text = (h.text(subject) + ". " + text).trim();
      if (!text) continue;
      if (own) outgoing++;
      else if (!from && sEl) from = { name: (sEl.getAttribute("name") || h.text(sEl) || "").trim() || null, address: addr || null };
      rows.push({ from: own ? "reader" : "sender", text, el: m });
    }
    const marked = !!(from && msgEls.some((m) => m.querySelector(SEL.trustedMark)));
    // stranger = no earlier reply from the reader in this thread and sender not marked as trusted
    const known = outgoing > 0 || marked;
    return { header: !!subject, sender: from || { name: null, address: null }, known_contact: known, rows };
  }

  // inbox list: unread rows (tr.zE) with sender, subject and snippet. The list cannot tell whether the reader ever replied,
  // so every unread sender counts as a stranger (full scan, local API only).
  const LIST = {
    item: ["tr.zA", "tr[role='row'].zA", "table[role='grid'] tr[role='row']"],
    unreadClass: "zE",
    sender: ["span[email]", ".yW span", ".zF"],
    subject: [".bog", ".bqe", "span.bqe"],
    snippet: [".y2", "span.y2"],
  };

  function list() {
    const out = [];
    for (const row of h.qAll(LIST.item)) {
      const sEl = h.q1(LIST.sender, row);
      if (!sEl) continue;
      const address = ((sEl.getAttribute("email")) || "").toLowerCase() || null;
      const name = (sEl.getAttribute("name") || h.text(sEl) || "").trim() || null;
      const preview = (h.text(h.q1(LIST.subject, row)) + ". " + h.text(h.q1(LIST.snippet, row)).replace(/^[-\s–]+/, "")).trim();
      out.push({ name, address, stranger: true, preview, unread: row.classList.contains(LIST.unreadClass), el: row });
    }
    return out;
  }

  SB.register({ name: "gmail", channel: "email", hostnames: ["mail.google.com"], scan, list });
})();
