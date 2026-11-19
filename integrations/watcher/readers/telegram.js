// @service telegram https://web.telegram.org/k/
// Telegram Web reader for both apps: /k (bubble is-in / is-out) and /a (.Message, .own). Unverified on a live account.
(function () {
  "use strict";
  if (!window.__SB) return;
  const SB = window.__SB, h = SB.h;

  const SEL = {
    k: {   // /k app
      chat: [".chat.active", ".chat", "#column-center"],
      title: [".chat-info .peer-title", ".chat-info .user-title", ".top .peer-title"],
      row: [".bubbles-inner .bubble[data-mid]", ".bubbles-inner .bubble", ".bubble"],
      outClass: "is-out",
      text: [".message", ".bubble-content .message"],
      drop: [".time", ".reply", ".reactions", ".inner", ".name", ".translatable-message-time"],
    },
    a: {   // /a app
      chat: ["#MiddleColumn", ".MessageList", "#middle-column"],
      title: [".ChatInfo .fullName", ".ChatInfo .title", ".MiddleHeader .ChatInfo h3", ".MiddleHeader .title"],
      row: [".messages-container .Message", ".MessageList .Message", ".Message"],
      outClass: "own",
      text: [".text-content", ".message-text .text-content"],
      drop: [".MessageMeta", ".message-time", ".Reactions", ".EmbeddedMessage"],
    },
    // a chat with somebody who is not a contact shows these action bars
    strangerBar: /add to contacts|adaug[ăa] .*contact|report spam|raporteaz[ăa] spam|block user|blocheaz[ăa]/i,
  };

  function scanApp(c) {
    const chat = h.q1(c.chat);
    if (!chat) return null;
    const title = h.text(h.q1(c.title, chat));
    const rows = [];
    for (const row of h.qAll(c.row, chat)) {
      const tEl = h.q1(c.text, row);
      if (!tEl) continue;
      const text = h.textWithout(tEl, c.drop);
      if (!text) continue;
      rows.push({ from: row.classList.contains(c.outClass) ? "reader" : "sender", text, el: row });
    }
    const phone = h.isPhone(title);
    const stranger = phone || h.hasControl(SEL.strangerBar, chat);
    return { header: !!title, sender: { name: phone ? null : (title || null), address: phone ? title : null },
             known_contact: !stranger, rows };
  }

  function scan() {
    return scanApp(location.pathname.indexOf("/a") === 0 ? SEL.a : SEL.k);
  }

  // chat list: the list does not show whether somebody is a saved contact, so every unread row is treated as a stranger
  // (full scan, nothing leaves the local API). Marking a contact as known (--show, "Îl cunosc") is the way to skip it.
  const LIST = {
    item: ["a.chatlist-chat", ".chatlist-chat", ".ChatList .ListItem.chat-item-clickable", ".ChatList .ListItem"],
    title: [".peer-title", ".dialog-title", ".fullName", ".title h3"],
    preview: [".user-last-message", ".dialog-subtitle .user-last-message", ".last-message", ".subtitle"],
    unread: ".badge.unread, .badge-unread, .dialog-subtitle-badge-unread, .Badge.unread, [class*='unread' i]",
  };

  function list() {
    const out = [];
    for (const row of h.qAll(LIST.item)) {
      const title = h.text(h.q1(LIST.title, row));
      const preview = h.text(h.q1(LIST.preview, row));
      if (!title) continue;
      const phone = h.isPhone(title);
      out.push({ name: phone ? null : title, address: phone ? title : null, stranger: true, preview,
                 unread: h.hasUnread(row, LIST.unread), el: row });
    }
    return out;
  }

  SB.register({ name: "telegram", channel: "chat", hostnames: ["web.telegram.org"], scan, list });
})();
