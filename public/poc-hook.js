// Nothing — POC verification hook (injected at document_start in the MAIN world).
// Overrides dialog primitives so that an executing XSS payload is *recorded*
// (flag on window) instead of popping a real modal that would block the tab.
// The background reads window.__NOTHING_POC_FIRED__ after the page settles.
(function () {
  try {
    if (window.__NOTHING_HOOKED__) return;
    window.__NOTHING_HOOKED__ = true;
    window.__NOTHING_POC_FIRED__ = false;
    window.__NOTHING_POC_MSG__ = '';

    var mark = function (val) {
      window.__NOTHING_POC_FIRED__ = true;
      try { window.__NOTHING_POC_MSG__ = String(val); } catch (e) {}
    };

    window.alert = function (m) { mark(m); };
    window.confirm = function (m) { mark(m); return true; };
    window.prompt = function (m) { mark(m); return ''; };
  } catch (e) { /* ignore */ }
})();
