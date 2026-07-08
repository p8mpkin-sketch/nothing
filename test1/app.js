// ============================================================
// test1/app.js
// 用于测试 Nothing 插件的 AI 漏洞分析：DOM XSS / Open Redirect / SSRF(前端)
// ============================================================

// DOM XSS 1: location.hash -> innerHTML
// POC: http://localhost:8888/#<img src=x onerror=alert(1)>
(function domXssFromHash() {
  var raw = location.hash.slice(1);
  if (!raw) return;
  document.getElementById('domxss_hash').innerHTML = decodeURIComponent(raw);
})();

// DOM XSS 2: query param -> innerHTML
// POC: http://localhost:8888/?name=<svg onload=alert(2)>
(function domXssFromQuery() {
  var params = new URLSearchParams(location.search);
  var name = params.get('name');
  if (!name) return;
  document.getElementById('domxss_query').innerHTML = 'Hello, ' + name;
})();

// DOM XSS 3: postMessage -> innerHTML (no origin check)
// POC: window.postMessage('<img src=x onerror=alert(3)>','*')
window.addEventListener('message', function (event) {
  if (typeof event.data !== 'string') return;
  document.getElementById('domxss_msg').innerHTML = 'Message: ' + event.data;
});

// Open Redirect: redirect parameter controls navigation
// POC: http://localhost:8888/?redirect=https://example.com
function goRedirect() {
  var params = new URLSearchParams(location.search);
  var u = params.get('redirect') || document.getElementById('redirInput').value;
  if (!u) return;
  // vulnerable: no allowlist / same-origin check
  location.href = u;
}

// SSRF (front-end): attacker-controlled URL used in fetch()
// POC: http://localhost:8888/?url=http://127.0.0.1:80
function doFetch() {
  var params = new URLSearchParams(location.search);
  var u = params.get('url') || document.getElementById('ssrfUrl').value;
  if (!u) return;
  fetch(u)
    .then(r => r.text())
    .then(t => {
      document.getElementById('ssrf_out').textContent = 'fetch ok, length=' + t.length;
    })
    .catch(e => {
      document.getElementById('ssrf_out').textContent = 'fetch error: ' + e.message;
    });
}

// SSRF (front-end): attacker-controlled URL used in XMLHttpRequest.open()
function doXHR() {
  var u = document.getElementById('xhrUrl').value;
  if (!u) return;
  var xhr = new XMLHttpRequest();
  xhr.open('GET', u, true);
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      document.getElementById('xhr_out').textContent = 'xhr status=' + xhr.status;
    }
  };
  xhr.send(null);
}

// Auto-run SSRF demos if query contains url
(function autoRun() {
  var params = new URLSearchParams(location.search);
  var u = params.get('url');
  if (u) {
    try { document.getElementById('ssrfUrl').value = u; } catch {}
    doFetch();
  }
  var r = params.get('redirect');
  if (r) {
    try { document.getElementById('redirInput').value = r; } catch {}
  }
})();
