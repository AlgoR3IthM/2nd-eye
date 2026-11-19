// 2nd Eye (Android): host shim injected BEFORE common.js and the reader.
// The desktop watcher gives the readers two exposed Playwright bindings, window.__sbAnalyze(payload) and
// window.__sbTrust(payload), both returning Promises. Here they sit on top of addJavascriptInterface("__SBNative").
// Kotlin answers through window.__sbResolve(id, jsonString). Config (window.__SB_CFG) is set by Kotlin before this file.
(function () {
  "use strict";
  if (window.__sbShim) return;
  window.__sbShim = true;
  var pending = {};
  var seq = 0;
  window.__sbResolve = function (id, json) {
    var cb = pending[id];
    if (!cb) return;
    delete pending[id];
    var v = null;
    try { v = JSON.parse(json); } catch (_) { v = null; }
    cb(v);
  };
  function call(method, arg) {
    return new Promise(function (resolve) {
      var id = ++seq;
      pending[id] = resolve;
      try {
        window.__SBNative[method](id, JSON.stringify(arg));
      } catch (_) {
        delete pending[id];
        resolve(null);
        return;
      }
      setTimeout(function () { if (pending[id]) { delete pending[id]; resolve(null); } }, 120000);
    });
  }
  window.__sbAnalyze = function (payload) { return call("analyze", payload); };   // -> {ok, known, result:{verdict,risk_score,first_alert,label,warning}}
  window.__sbTrust = function (payload) { return call("trust", payload); };       // -> true | false
})();
