// Nothing — POC verification hook (injected at document_start in the MAIN world).
// Records XSS execution via multiple side channels, not just alert():
//
//   Channel 1: window.__NOTHING_POC_FIRED__ (alert/confirm/prompt call)
//   Channel 2: document.title contains marker
//   Channel 3: document.cookie contains marker
//   Channel 4: window.__NOTHING_POC_TITLE__  (title set by eval-like contexts)
//
// The background reads ALL channels after the page settles.
(function () {
  try {
    if (window.__NOTHING_HOOKED__) return;
    window.__NOTHING_HOOKED__ = true;
    window.__NOTHING_POC_FIRED__ = false;
    window.__NOTHING_POC_MSG__ = '';
    window.__NOTHING_POC_TITLE__ = null;
    window.__NOTHING_POC_COOKIE__ = null;

    var mark = function (val) {
      window.__NOTHING_POC_FIRED__ = true;
      try { window.__NOTHING_POC_MSG__ = String(val); } catch (e) {}
    };

    window.alert = function (m) { mark(m); };
    window.confirm = function (m) { mark(m); return true; };
    window.prompt = function (m) { mark(m); return ''; };
  } catch (e) { /* ignore */ }
})();
