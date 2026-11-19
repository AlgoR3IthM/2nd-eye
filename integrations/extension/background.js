// Service worker: the only place that talks to the local API (localhost:8000).
// Message text is forwarded, never stored or logged.
const API = "http://localhost:8000";

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "analyze") return false;
  const url = API + "/api/analyze" + (msg.trustGate ? "?trust_gate=true" : "");
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg.scenario),
  })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("http " + r.status))))
    .then((data) => sendResponse({ ok: true, data }))
    .catch(() => sendResponse({ ok: false }));
  return true; // async response
});
