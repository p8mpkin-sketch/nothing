// Content script - runs in page context
// scanner.config.js and scanner.filter.js are injected before this via manifest content_scripts order

(function () {
    'use strict';

    const CONFIG = window.SCANNER_CONFIG;
    const FILTER = window.SCANNER_FILTER;

    if (!CONFIG || !FILTER) {
        console.warn('[Nothing] Scanner config not loaded');
        return;
    }

    const results = {}; // category -> Set of strings
    const scannedJsUrls = new Set();

    function initCategory(cat) {
        if (!results[cat]) results[cat] = new Set();
    }

    function scanText(text, source) {
        if (!text || text.length < 4) return;

        for (const [category, config] of Object.entries(CONFIG)) {
            initCategory(category);
            for (const pattern of config.patterns) {
                // Reset lastIndex for global patterns
                pattern.lastIndex = 0;
                let match;
                while ((match = pattern.exec(text)) !== null) {
                    const value = match[1] || match[0];
                    if (!value) continue;

                    // Category-specific filtering
                    if (category === 'ip') {
                        // Only report internal/private IPs (10/172.16-31/192.168/127/…).
                        // Public "IPs" in front-end code are almost always noise
                        // (versions, coordinates); internal-IP leakage is the real signal.
                        if (!FILTER.isPrivateIP(value)) continue;
                    } else if (category === 'api') {
                        let path = FILTER.decodeEntities(value.slice(1, -1)); // strip quotes + decode &amp;
                        if (FILTER.isBoringPath(path)) continue;
                        if (FILTER.isJunkResource(path)) continue;
                        // Downloadable-artifact files are reported under 'docFile', not API.
                        if (/\.(?:exe|msi|apk|dmg|pkg|docx?|xlsx?|pptx?|pdf|rtf|zip|rar|7z|tar|gz|tgz|sql|bak)(?:\?|$)/i.test(path)) continue;
                        // Collapse query-value floods (/x?id=1, /x?id=2 … -> /x?id)
                        path = FILTER.normalizeApiPath(path);
                        if (path.startsWith('/')) {
                            initCategory('absoluteApi');
                            results['absoluteApi'].add(FILTER.truncate(path));
                        } else {
                            results['api'].add(FILTER.truncate(path));
                        }
                        continue;
                    } else if (category === 'credential') {
                        const secret = match[2] || match[1];
                        if (!FILTER.isRealSecret(secret)) continue;

                        // Additional filtering: skip if value looks like an API path/URL
                        if (/^\//.test(secret)) {
                            // e.g. password="/open-server/developer/password/new" or token="/v3.0/open/access_token"
                            // value 以 / 开头说明是路径定义，不是真密钥
                            continue;
                        }

                        // Enhanced: add source location and context window
                        const matchIndex = match.index;
                        const contextBefore = 40;
                        const contextAfter = 40;
                        const start = Math.max(0, matchIndex - contextBefore);
                        const end = Math.min(text.length, matchIndex + fullMatch.length + contextAfter);
                        const contextSnippet = text.slice(start, end);

                        // Format: [SOURCE:location] credential_value | CONTEXT: snippet
                        let sourceLabel = 'UNKNOWN';
                        if (source === 'html') {
                            sourceLabel = 'HTML';
                        } else if (source === 'inline-script') {
                            sourceLabel = 'INLINE_SCRIPT';
                        } else if (source === 'meta') {
                            sourceLabel = 'META_TAG';
                        } else if (source.startsWith('external-js:')) {
                            // Extract URL from source
                            const url = source.replace('external-js:', '');
                            sourceLabel = `JS:${url}`;
                        } else if (source.startsWith('dynamic-js:')) {
                            const url = source.replace('dynamic-js:', '');
                            sourceLabel = `DYNAMIC_JS:${url}`;
                        } else if (source.startsWith('dynamic-script')) {
                            sourceLabel = 'DYNAMIC_SCRIPT';
                        }

                        const enriched = `[${sourceLabel}] ${FILTER.truncate(fullMatch)} | CONTEXT: ${contextSnippet.replace(/\s+/g, ' ').trim()}`;
                        results[category].add(enriched);
                        continue;
                    }

                    // URL category: drop junk (data-URI, w3.org svg ns, extension urls)
                    if (category === 'url' && FILTER.isJunkResource(value)) continue;

                    results[category].add(FILTER.truncate(value));
                }
            }
        }
    }

    function scanDOM() {
        // Scan full HTML content (catches API paths, emails, keys in attributes/text)
        const html = document.documentElement.innerHTML;
        if (html) {
            scanText(html, 'html');
            for (const r of extractRoutes(html)) { initCategory('route'); results['route'].add(r); }
        }

        // Scan inline scripts (more focused scan)
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(s => {
            scanText(s.textContent, 'inline-script');
            if (s.textContent) for (const r of extractRoutes(s.textContent)) { initCategory('route'); results['route'].add(r); }
        });

        // Scan meta tags
        const metas = document.querySelectorAll('meta[content]');
        metas.forEach(m => scanText(m.getAttribute('content'), 'meta'));

        // Extra: collect lightweight reflected-XSS evidence (query params + inline script snippets)
        collectReflectedXssEvidence();
    }

    // Collect evidence for "Reflected XSS / JS string injection" where query params are reflected into inline <script>
    function collectReflectedXssEvidence() {
        try {
            if (!location.search || location.search.length < 2) return;

            const params = new URLSearchParams(location.search);
            const highRiskCharRe = /["'<>;()\n\r\\]/;
            const riskKeyRe = /^(name|msg|message|q|query|search|keyword|call|redirect|url|next|return|callback)$/i;

            const pageParamEntries = [];
            for (const [key, valueRaw] of params.entries()) {
                if (pageParamEntries.length >= 10) break;
                const value = (valueRaw || '').trim();
                if (!value) continue;

                // Keep only meaningful values:
                // - contains risky chars, OR
                // - length >= 3 (likely user input), OR
                // - short but high-signal keys (e.g., message/call/url)
                const meaningful = highRiskCharRe.test(value) || (value.length >= 3 && value.length <= 200) || (value.length < 3 && riskKeyRe.test(key));
                if (!meaningful) continue;

                const truncatedValue = value.length > 220 ? value.slice(0, 220) + '…' : value;
                pageParamEntries.push({ key, value: truncatedValue });
            }

            if (pageParamEntries.length === 0) return;

            initCategory('pageParamSample');
            for (const p of pageParamEntries) {
                results['pageParamSample'].add(`PARAM: ${p.key}=${p.value}`);
            }

            // 1. 检查参数是否反射到HTML中（传统反射型XSS）
            const bodyHTML = document.body ? document.body.innerHTML : '';
            let htmlReflectionCount = 0;
            for (const p of pageParamEntries) {
                if (htmlReflectionCount >= 5) break;
                const idx = bodyHTML.indexOf(p.value);
                if (idx !== -1) {
                    const windowBefore = 200;
                    const windowAfter = 200;
                    const start = Math.max(0, idx - windowBefore);
                    const end = Math.min(bodyHTML.length, idx + windowAfter);
                    let snippet = bodyHTML.slice(start, end);
                    if (snippet.length > 800) snippet = snippet.slice(0, 800) + '…';

                    // 清理snippet中的换行和多余空格
                    snippet = snippet.replace(/\s+/g, ' ').trim();

                    initCategory('inlineScriptSinkSnippet');
                    results['inlineScriptSinkSnippet'].add(`HTML_REFLECTION (param: ${p.key}): ${snippet}`);
                    htmlReflectionCount++;
                }
            }

            // 2. 检查参数是否反射到内联脚本中（DOM XSS）
            const inlineScripts = document.querySelectorAll('script:not([src])');
            let snippetCount = 0;
            for (const s of inlineScripts) {
                if (snippetCount >= 5) break;
                const text = s.textContent || '';
                if (!text || text.length < 20) continue;

                // Prefer matching by decoded value; fallback to matching key
                let hit = null;
                for (const p of pageParamEntries) {
                    const idx = text.indexOf(p.value);
                    if (idx !== -1) { hit = { key: p.key, idx, kind: 'value' }; break; }
                }
                if (!hit) {
                    for (const p of pageParamEntries) {
                        const idx = text.indexOf(p.key);
                        if (idx !== -1) { hit = { key: p.key, idx, kind: 'key' }; break; }
                    }
                }
                if (!hit) continue;

                const windowBefore = 250;
                const windowAfter = 350;
                const start = Math.max(0, hit.idx - windowBefore);
                const end = Math.min(text.length, hit.idx + windowAfter);
                let snippet = text.slice(start, end);
                if (snippet.length > 1200) snippet = snippet.slice(0, 1200) + '…';

                initCategory('inlineScriptSnippet');
                results['inlineScriptSnippet'].add(`INLINE_SCRIPT_SNIPPET (hit ${hit.kind}: ${hit.key}): ${snippet}`);
                snippetCount++;
            }

            // If no direct reflection hit, still capture a few "sink" snippets as weaker evidence
            // This helps cases where the server reflects param into a different key (e.g., message -> call)
            // or only becomes obvious after certain interactions.
            if (snippetCount === 0 && htmlReflectionCount === 0) {
                const sinkRe = /(window\.)?location\.href\s*=|location\.assign\s*\(|location\.replace\s*\(|document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(|setInterval\s*\(|XMLHttpRequest\s*\(|\bfetch\s*\(|\baxios\s*\(/i;
                let sinkCount = 0;
                for (const s of inlineScripts) {
                    if (sinkCount >= 3) break;
                    const text = s.textContent || '';
                    if (!text || text.length < 20) continue;
                    const m = text.match(sinkRe);
                    if (!m || m.index == null) continue;

                    const windowBefore = 250;
                    const windowAfter = 350;
                    const start = Math.max(0, m.index - windowBefore);
                    const end = Math.min(text.length, m.index + windowAfter);
                    let snippet = text.slice(start, end);
                    if (snippet.length > 1200) snippet = snippet.slice(0, 1200) + '…';

                    initCategory('inlineScriptSinkSnippet');
                    results['inlineScriptSinkSnippet'].add(`INLINE_SCRIPT_SINK_SNIPPET: ${snippet}`);
                    sinkCount++;
                }
            }
        } catch (e) {
            // best-effort, do not break scanning
        }
    }

    function scanDOMElements() {
        // Iframes
        document.querySelectorAll('iframe').forEach(el => {
            const src = el.getAttribute('src');
            if (!src || FILTER.isJunkResource(src)) return;
            initCategory('iframe');
            results['iframe'].add(src);
        });

        // Images, audio, video, favicon
        document.querySelectorAll('img[src],audio[src],video[src],source[src],link[rel*="icon"][href]').forEach(el => {
            const src = el.getAttribute('src') || el.getAttribute('href');
            if (src && src.length > 1 && !FILTER.isJunkResource(src)) {
                initCategory('image');
                results['image'].add(src);
            }
        });

        // JS files from external script tags
        document.querySelectorAll('script[src]').forEach(el => {
            const src = el.getAttribute('src');
            if (!src) return;
            initCategory('jsFile');
            results['jsFile'].add(src);
        });

        // External domains from all elements with src/href
        document.querySelectorAll('[src],[href]').forEach(el => {
            const val = el.getAttribute('src') || el.getAttribute('href') || '';
            if (!val.startsWith('http')) return;
            try {
                const url = new URL(val);
                if (url.hostname !== location.hostname && !/w3\.org$/i.test(url.hostname)) {
                    initCategory('domain');
                    results['domain'].add(url.hostname);
                }
            } catch (e) {}
        });
    }

    function getResultsSnapshot() {
        const snapshot = {};
        for (const [cat, set] of Object.entries(results)) {
            const arr = [...set];
            if (arr.length > 0) snapshot[cat] = arr;
        }
        return snapshot;
    }

    function reportResults() {
        const snapshot = getResultsSnapshot();
        if (Object.keys(snapshot).length === 0) return;

        chrome.runtime.sendMessage({
            action: 'SCAN_RESULTS',
            data: snapshot,
            url: location.href,
        }).catch(() => {});
    }

    // Skip known third-party libraries to avoid noise
    function isThirdPartyLib(url) {
        const name = url.split('/').pop()?.split('?')[0]?.toLowerCase() || '';
        return /^(jquery|vue|react|angular|bootstrap|lodash|moment|axios|echarts|layui|element|antd|core-js|polyfill)[.-]/i.test(name);
    }

    function resolveUrl(u) {
        try { return new URL(u, location.href).href; } catch { return null; }
    }

    // Extract front-end route paths (Vue Router / React Router style) from JS/HTML text.
    // Whether a reconstructed path looks like a real front-end route.
    function isRoutePath(p) {
        if (!p || p.length > 160) return false;
        if (!p.startsWith('/')) return false;
        if (/[<>\s"'`]|%3c|%3e/i.test(p)) return false;                 // markup/junk
        if (/\.(?:js|mjs|css|png|jpe?g|svg|gif|webp|woff2?|ttf|ico|json)$/i.test(p)) return false;
        if (/^\/(?:assets|static|public)\//.test(p)) return false;
        return true;
    }

    function joinRoute(stack, p) {
        if (p.startsWith('/')) return p.replace(/\/+/g, '/');           // absolute path resets
        let base = '';
        for (const s of stack) {
            if (!s) continue;
            base = s.startsWith('/') ? s : (base.replace(/\/+$/, '') + '/' + s);
        }
        return ((base ? base.replace(/\/+$/, '') : '') + '/' + p).replace(/\/+/g, '/');
    }

    // Skip a JS string literal starting at index i (i points at the quote).
    function skipStr(text, i) {
        const q = text[i]; i++;
        const n = text.length;
        while (i < n) {
            const c = text[i];
            if (c === '\\') { i += 2; continue; }
            if (c === q) return i + 1;
            i++;
        }
        return i;
    }

    // Find the ']' matching the '[' at index `open`, skipping brackets inside strings.
    function matchBracket(text, open) {
        let depth = 0, i = open;
        const n = text.length;
        while (i < n) {
            const c = text[i];
            if (c === '"' || c === "'" || c === '`') { i = skipStr(text, i); continue; }
            if (c === '[') depth++;
            else if (c === ']') { depth--; if (depth === 0) return i; }
            i++;
        }
        return -1;
    }

    // Extract front-end routes (Vue Router / React Router) with NESTED reconstruction.
    // String-AWARE: locate every `path:"X"` and every `children:[…]` range (matching
    // brackets while skipping string contents — minified bundles are full of `[` `]`
    // inside strings), then derive each route's parents by containment.
    function extractRoutes(text) {
        if (!text || text.length > 8000000) return [];

        const paths = [];
        const pathRe = /path\s*:\s*(["'`])((?:\\.|(?!\1).)*)\1/g;
        let m;
        while ((m = pathRe.exec(text)) !== null) {
            paths.push({ pos: m.index, val: m[2] });
            if (paths.length > 4000) break;
        }
        if (!paths.length) return [];

        const ranges = [];
        const childRe = /children\s*:\s*\[/g;
        while ((m = childRe.exec(text)) !== null) {
            const open = childRe.lastIndex - 1;
            const end = matchBracket(text, open);
            if (end > open) ranges.push({ open, end });
            if (ranges.length > 3000) break;
        }

        const pathBefore = (pos) => {
            let best = null;
            for (const p of paths) { if (p.pos < pos && (!best || p.pos > best.pos)) best = p; }
            return best;
        };
        const innerRange = (pos) => {
            let inner = null;
            for (const r of ranges) { if (r.open < pos && pos < r.end && (!inner || r.open > inner.open)) inner = r; }
            return inner;
        };
        const cache = new Map();
        function prefixFor(pos) {
            if (cache.has(pos)) return cache.get(pos);
            cache.set(pos, []); // guard against cycles
            const r = innerRange(pos);
            let res = [];
            if (r) { const parent = pathBefore(r.open); if (parent) res = [...prefixFor(parent.pos), parent.val]; }
            cache.set(pos, res);
            return res;
        }

        const out = new Set();
        for (const p of paths) {
            const full = joinRoute(prefixFor(p.pos), p.val);
            if (isRoutePath(full)) out.add(full);
            if (out.size > 1000) break;
        }
        return [...out];
    }

    // Best-effort webpack chunk enumeration: read the chunk id->hash map and the
    // filename template from a runtime/entry chunk, and rebuild the lazy-loaded
    // chunk URLs. Over-generation is harmless (missing chunks just 404).
    function extractWebpackChunks(jsText, baseUrl) {
        if (!/webpackChunk|webpackJsonp|__webpack_require__/.test(jsText)) return [];
        const urls = new Set();

        // publicPath: __webpack_require__.p = "..."  (fallback to the JS file's dir)
        let publicPath = '';
        const pp = jsText.match(/\.p\s*=\s*["'`]([^"'`]*?)["'`]/);
        if (pp && pp[1]) publicPath = pp[1];
        const baseDir = baseUrl ? baseUrl.replace(/[^/]*$/, '') : location.href;

        // JS chunk filename builder region: `.u = <expr ending in ".js"|".chunk.js">`.
        // Capture lazily up to the terminating ".js" literal (the chunk hash map in
        // between contains `}`, so we must NOT stop at braces).
        const builderRe = /\.u\s*=\s*([\s\S]{0,1200}?(?:\.chunk\.js|\.js)")/g;
        let bm;
        while ((bm = builderRe.exec(jsText)) !== null) {
            const region = bm[1];
            const mapMatch = region.match(/\{((?:\s*"?\d+"?\s*:\s*"[0-9a-zA-Z_.-]+"\s*,?)+)\}/);
            if (!mapMatch) continue;

            const idHash = {};
            const pairRe = /"?(\d+)"?\s*:\s*"([0-9a-zA-Z_.-]+)"/g;
            let p;
            while ((p = pairRe.exec(mapMatch[1])) !== null) idHash[p[1]] = p[2];

            // Literals before the map = path prefix; after the map = suffix (e.g. ".js").
            const mapPos = region.indexOf(mapMatch[0]);
            const before = region.slice(0, mapPos);
            const after = region.slice(mapPos + mapMatch[0].length);
            const beforeLits = [...before.matchAll(/"([^"]*)"/g)].map(x => x[1]);
            const afterLits = [...after.matchAll(/"([^"]*)"/g)].map(x => x[1]);
            const prefix = beforeLits.find(l => l.includes('/')) ?? '';
            const suffix = afterLits.join('') || '.js';

            for (const id of Object.keys(idHash).slice(0, 200)) {
                const fname = `${prefix}${id}.${idHash[id]}${suffix}`;
                const rooted = publicPath
                    ? publicPath.replace(/\/$/, '') + '/' + fname.replace(/^\//, '')
                    : fname;
                const full = resolveUrl(/^(?:https?:)?\/\//.test(rooted) || rooted.startsWith('/') ? rooted : baseDir + rooted);
                if (full && /\.js(?:\?|$)/.test(full)) urls.add(full);
            }
        }
        return [...urls];
    }

    // Fetch and scan external JS files via background (deepScan must be enabled).
    // Follows webpack chunk maps to enumerate lazy-loaded module files, and
    // extracts front-end routes along the way.
    async function scanExternalJS() {
        try {
            const res = await chrome.runtime.sendMessage({ action: 'GET_SETTINGS' });
            if (!res?.settings?.deepScan) return;
        } catch (e) { return; }

        const MAX_JS = 150; // safety cap on total JS files fetched per page
        const queue = [];
        document.querySelectorAll('script[src]').forEach(el => {
            const src = el.getAttribute('src');
            const u = src && resolveUrl(src);
            if (u) queue.push(u);
        });

        let fetched = 0;
        while (queue.length && fetched < MAX_JS) {
            const url = queue.shift();
            if (!url || scannedJsUrls.has(url) || isThirdPartyLib(url)) continue;
            scannedJsUrls.add(url);
            const jsRes = await chrome.runtime.sendMessage({ action: 'FETCH_JS', url }).catch(() => null);
            fetched++;
            const content = jsRes?.content;
            if (!content) continue;

            scanText(content, `external-js:${url}`);

            // Front-end routes
            for (const r of extractRoutes(content)) { initCategory('route'); results['route'].add(r); }

            // Webpack lazy chunks -> record as module files and enqueue for scanning
            for (const chunkUrl of extractWebpackChunks(content, url)) {
                initCategory('moduleFile');
                results['moduleFile'].add(chunkUrl.replace(location.origin, ''));
                if (!scannedJsUrls.has(chunkUrl) && !isThirdPartyLib(chunkUrl)) queue.push(chunkUrl);
            }

            reportResults();
        }
    }

    // Initial DOM scan
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            scanDOM();
            scanDOMElements();
            scanExternalJS();
            reportResults();
        });
    } else {
        scanDOM();
        scanDOMElements();
        scanExternalJS();
        reportResults();
    }

    // Watch for dynamic script injection
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeName === 'SCRIPT' && !node.src) {
                    scanText(node.textContent, 'dynamic-script');
                } else if (node.nodeName === 'SCRIPT' && node.src) {
                    // New external script added dynamically
                    const url = node.src;
                    if (!scannedJsUrls.has(url) && !isThirdPartyLib(url)) {
                        scannedJsUrls.add(url);
                        chrome.runtime.sendMessage({ action: 'FETCH_JS', url })
                            .then(r => { if (r?.content) { scanText(r.content, `dynamic-js:${url}`); reportResults(); } })
                            .catch(() => {});
                    }
                }
            }
        }
    });

    observer.observe(document.documentElement, { childList: true, subtree: true });

    // Periodic re-report for SPAs
    setInterval(() => {
        scanDOM();
        scanDOMElements();
        reportResults();
    }, 5000);

})();
