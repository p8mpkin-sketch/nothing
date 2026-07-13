import { getParentHierarchies } from './urlParser';
import { ruleEngine } from './ruleEngine';
import { activeScanner } from './scanner';
import { backupScanner } from './backupScanner';
import { networkMonitor, tabJsMap, tabFingerprints } from './networkMonitor';
import { queryICP, queryIPInfo, isInternalHost } from './siteAnalysis';
import { staticXssDetector } from './staticXssDetector';
import { verifyXssFindings } from './pocVerifier';
import { getProvider, resolveAiUrl } from '../utils/aiProviders';
import { generatePocs, parseReflectionContext, extractParamNames, extractParamValue, wafStrategy, CTX, ENC } from './pocEngine';
import { runPipeline } from './detectionPipeline';

// Build deterministic POC candidates for reflected XSS (post-process AI result)
function guessQuoteFromInlineSnippets(inlineSnippets = []) {
    const joined = (inlineSnippets || []).join('\n');
    // Heuristic: if we see single-quoted assignment, prefer '\''
    if (/\b(?:href|location\.href)\s*=\s*'/.test(joined) || /'[^']*\b(call|message)=/.test(joined)) return '\'';
    return '"';
}

function extractLikelyParamName(vuln, pageParams = []) {
    const text = [vuln?.source, vuln?.chain, vuln?.analysis].filter(Boolean).join('\n');
    const m1 = text.match(/\bQuery\s*parameter\s*:\s*([a-zA-Z0-9_]+)/i);
    if (m1?.[1]) return m1[1];
    const m2 = text.match(/\bparameter\s*:\s*([a-zA-Z0-9_]+)/i);
    if (m2?.[1]) return m2[1];
    const m3 = text.match(/\b([a-zA-Z0-9_]+)\s*=\s*\.\.\./);
    if (m3?.[1]) return m3[1];

    const preferred = ['message', 'msg', 'call', 'q', 'query', 'search', 'keyword', 'redirect', 'url', 'next', 'return', 'callback'];
    for (const key of preferred) {
        const hit = pageParams.find(p => typeof p === 'string' && new RegExp(`^PARAM:\\s*${key}=`, 'i').test(p));
        if (hit) return hit.split(':')[1].trim().split('=')[0];
    }
    const first = pageParams.find(p => typeof p === 'string' && p.startsWith('PARAM: '));
    if (first) return first.split(':')[1].trim().split('=')[0];
    return null;
}

/**
 * 使用 pocEngine 生成上下文感知的 POC payload。
 * 替代原有的硬编码 buildReflectedXssPayloads。
 */
function buildReflectedXssPayloads(quoteChar = '"', context = {}) {
    const { snippet = '', framework = '' } = context;
    const paramValue = context.paramValue || 'REF';

    // 用 pocEngine 解析上下文 → 生成 POC
    const parsed = parseReflectionContext(snippet, paramValue);
    if (!parsed || parsed.exploitability <= 0) {
        // 兜底：即使 pocEngine 没有识别出上下文，也给几条通用 payload
        const q = quoteChar === "'" ? "'" : '"';
        return [...new Set([
            `${q}}a=\\u0061lert,a\`1\`,{//`,
            `${q};a=\\u0061lert,a\`1\`;//`,
            `${q};alert(document.domain)//`,
        ])];
    }

    // 让 pocEngine 生成 POC payloads
    // generatePocs 返回的每个结果都带 { url, payload, strategy }，直接取 payload
    const mockUrl = 'http://x/_?x=1';
    const pocs = generatePocs(parsed, mockUrl, 'x');
    if (!pocs || pocs.length === 0) {
        const q = quoteChar === "'" ? "'" : '"';
        return [`${q}}a=\\u0061lert,a\`1\`,{//`];
    }

    // 直接取原始 payload 字符串，不靠 URL 反猜
    return [...new Set(pocs.map(p => p.payload).filter(Boolean))].slice(0, 12);
}

function buildPocUrls(pageUrl, paramName, payloads) {
    const out = [];
    if (!pageUrl || !paramName || !Array.isArray(payloads) || payloads.length === 0) return out;
    let base;
    try { base = new URL(pageUrl); } catch { return out; }

    for (const raw of payloads) {
        try {
            const u = new URL(base.href);
            u.searchParams.set(paramName, raw);
            out.push(u.toString());
        } catch {}
    }
    return out;
}

// ── Reflected XSS: Parameter Reflection Probe (same-origin, lightweight) ───────
function shouldProbeReflection(scanData = {}, settings = {}) {
    // Reuse activeScan as the master switch for probe
    if (!settings?.activeScan) return false;

    const pageParams = scanData.pageParamSample || [];
    const inlineSnippets = scanData.inlineScriptSnippet || [];
    const inlineSinkSnippets = scanData.inlineScriptSinkSnippet || [];

    // Basic gate: need params, no direct reflection, but have sink evidence
    if (!(Array.isArray(pageParams) && pageParams.length > 0 &&
          Array.isArray(inlineSnippets) && inlineSnippets.length === 0 &&
          Array.isArray(inlineSinkSnippets) && inlineSinkSnippets.length > 0)) {
        return false;
    }

    // Analyze sink quality: prioritize high-risk sinks
    const sinkText = inlineSinkSnippets.join('\n');
    const highRiskSinks = /\beval\s*\(|new\s+Function\s*\(|innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(/i;
    const mediumRiskSinks = /location\.(href|assign|replace)\s*[=(]|setTimeout\s*\(|setInterval\s*\(/i;

    const hasHighRiskSink = highRiskSinks.test(sinkText);
    const hasMediumRiskSink = mediumRiskSinks.test(sinkText);

    // Only probe if we have at least medium-risk sinks
    if (!hasHighRiskSink && !hasMediumRiskSink) return false;

    // Check if page looks dynamic (JS framework indicators)
    const hasDynamicIndicators = /\b(vue|react|angular|__NEXT_DATA__|__NUXT__|ng-app|v-if|data-reactroot)\b/i.test(sinkText);

    // Boost confidence if dynamic framework detected
    return hasHighRiskSink || hasMediumRiskSink || hasDynamicIndicators;
}

function parseParamSamples(pageParamSample = []) {
    const out = [];
    for (const s of pageParamSample || []) {
        if (typeof s !== 'string') continue;
        // "PARAM: key=value"
        const m = s.match(/^PARAM:\s*([^=\s]+)=(.*)$/);
        if (!m) continue;
        out.push({ key: m[1], value: m[2] || '' });
    }
    return out;
}

function pickProbeParams(pageParamSample = []) {
    const entries = parseParamSamples(pageParamSample);
    if (entries.length === 0) return [];

    // Score each parameter based on risk indicators
    const scored = entries.map(e => {
        let score = 0;
        const key = e.key.toLowerCase();
        const value = e.value || '';

        // High-risk parameter names (highest priority)
        const highRiskKeys = ['message', 'msg', 'call', 'callback', 'url', 'redirect', 'next', 'return'];
        if (highRiskKeys.includes(key)) score += 100;

        // Medium-risk parameter names
        const mediumRiskKeys = ['q', 'query', 'search', 'keyword', 'text', 'content', 'data', 'input'];
        if (mediumRiskKeys.includes(key)) score += 50;

        // Value characteristics
        if (value.length >= 6 && value.length <= 200) score += 20; // Reasonable user input length
        if (/["'<>;()\n\r\\]/.test(value)) score += 30; // Contains risky characters
        if (/^[a-zA-Z0-9_-]+$/.test(value) && value.length < 20) score += 10; // Simple identifier-like
        if (/^\d+$/.test(value)) score += 5; // Pure numeric (lower priority but still probe-worthy)

        // Position weight: earlier params often more important
        const position = entries.indexOf(e);
        score += Math.max(0, 10 - position);

        return { ...e, score };
    });

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score);

    // Dynamic selection: pick 1-3 params based on score distribution
    const picked = [];
    const topScore = scored[0]?.score || 0;

    for (const entry of scored) {
        if (picked.length >= 3) break;

        // Always pick top scorer
        if (picked.length === 0) {
            picked.push(entry.key);
            continue;
        }

        // Pick additional params if they're reasonably high-scoring
        if (entry.score >= topScore * 0.5 || entry.score >= 50) {
            picked.push(entry.key);
        } else if (picked.length < 2 && entry.score >= 20) {
            // Ensure at least 2 params if available
            picked.push(entry.key);
        }
    }

    return picked.slice(0, 3);
}

function buildProbeUrl(pageUrl, paramName, marker) {
    if (!pageUrl || !paramName || !marker) return null;
    let u;
    try { u = new URL(pageUrl); } catch { return null; }

    // Only probe http(s)
    if (!(u.protocol === 'http:' || u.protocol === 'https:')) return null;

    // Keep other params unchanged, only replace one param
    const out = new URL(u.toString());
    out.searchParams.set(paramName, marker);
    return out.toString();
}

async function fetchHtml(url) {
    try {
        const r = await fetch(url, {
            credentials: 'include',
            redirect: 'manual',
            signal: AbortSignal.timeout(4000),
        });
        const text = await r.text();
        return (text || '').slice(0, 120000);
    } catch {
        return null;
    }
}

function extractInlineProbeSnippets(html, { marker, paramName } = {}) {
    if (!html || !marker) return [];

    const snippets = [];
    const re = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
        const scriptBody = m[1] || '';
        if (!scriptBody) continue;
        const idx = scriptBody.indexOf(marker);
        if (idx === -1) continue;

        const windowBefore = 250;
        const windowAfter = 350;
        const start = Math.max(0, idx - windowBefore);
        const end = Math.min(scriptBody.length, idx + windowAfter);
        let snippet = scriptBody.slice(start, end);
        if (snippet.length > 1200) snippet = snippet.slice(0, 1200) + '…';

        const label = `INLINE_SCRIPT_PROBE_SNIPPET (param=${paramName || 'unknown'}, marker=${marker}): `;
        snippets.push(label + snippet);

        if (snippets.length >= 5) break;
    }

    return snippets;
}

function buildProbeCacheKey(tabId, pageUrl) {
    if (!tabId || !pageUrl) return null;
    try {
        const u = new URL(pageUrl);
        const keys = [...u.searchParams.keys()].sort();
        const normalizedPath = `${u.origin}${u.pathname}`;
        return `${tabId}|${normalizedPath}|${keys.join(',')}`;
    } catch {
        return null;
    }
}

function mergeProbeSnippetsToScan(tabId, snippets = []) {
    if (!tabId || !Array.isArray(snippets) || snippets.length === 0) return;
    if (!tabScanResults[tabId]) tabScanResults[tabId] = {};
    if (!tabScanResults[tabId].inlineScriptProbeSnippet) tabScanResults[tabId].inlineScriptProbeSnippet = [];

    const existing = new Set(tabScanResults[tabId].inlineScriptProbeSnippet);
    for (const s of snippets) existing.add(s);
    tabScanResults[tabId].inlineScriptProbeSnippet = [...existing].slice(0, 5);
}

async function probeParamReflection(tabId, pageUrl, pageParamSample = []) {
    const cacheKey = buildProbeCacheKey(tabId, pageUrl);
    if (!cacheKey) return [];

    // Cache hit
    const cached = probeCache.get(cacheKey);
    if (cached?.snippets?.length) {
        mergeProbeSnippetsToScan(tabId, cached.snippets);
        return cached.snippets;
    }

    // Request deduplication: if same probe is already running, wait for it
    if (pendingProbeRequests.has(cacheKey)) {
        try {
            const result = await pendingProbeRequests.get(cacheKey);
            mergeProbeSnippetsToScan(tabId, result);
            return result;
        } catch {
            return [];
        }
    }

    // Prevent concurrent probe per tab
    if (!tabProbeStatus[tabId]) tabProbeStatus[tabId] = {};
    if (tabProbeStatus[tabId].running) return [];
    if (tabProbeStatus[tabId].done && tabProbeStatus[tabId].cacheKey === cacheKey) return [];

    tabProbeStatus[tabId] = { running: true, done: false, cacheKey };

    // Create promise for deduplication
    const probePromise = (async () => {
        try {
            const marker = `NOTING_PROBE_${Math.random().toString(36).slice(2, 9)}`;
            const paramsToProbe = pickProbeParams(pageParamSample);

            const allSnippets = [];
            let requests = 0;
            const maxRequests = 6;

            for (const paramName of paramsToProbe) {
                if (requests >= maxRequests) break;

                const probeUrl = buildProbeUrl(pageUrl, paramName, marker);
                if (!probeUrl) continue;

                requests++;
                const html = await fetchHtml(probeUrl);
                if (!html) continue;

                const snippets = extractInlineProbeSnippets(html, { marker, paramName });
                for (const s of snippets) allSnippets.push(s);
                if (allSnippets.length >= 5) break;
            }

            const finalSnippets = [...new Set(allSnippets)].slice(0, 5);
            if (finalSnippets.length > 0) {
                mergeProbeSnippetsToScan(tabId, finalSnippets);
            }

            // Cache result
            probeCache.set(cacheKey, { snippets: finalSnippets });

            tabProbeStatus[tabId] = { running: false, done: true, cacheKey };
            return finalSnippets;
        } finally {
            // Clean up pending request
            pendingProbeRequests.delete(cacheKey);
        }
    })();

    pendingProbeRequests.set(cacheKey, probePromise);
    return probePromise;
}

function enrichReflectedXssPocs(result, { pageUrl, pageParams, inlineSnippets } = {}) {
    if (!result || typeof result !== 'object') return result;
    const vulns = Array.isArray(result.vulnerabilities) ? result.vulnerabilities : [];
    if (vulns.length === 0) return result;

    const snippetText = (inlineSnippets || []).join('\n');
    const paramNames = extractParamNames(pageParams || []);

    const enriched = vulns.map(v => {
        if (!v || typeof v.type !== 'string' || !v.type.startsWith('Reflected XSS')) return v;

        const paramName = extractLikelyParamName(v, pageParams) || paramNames[0] || 'message';

        // 用 pocEngine 生成上下文感知的 POC
        // 从 snippet 中找出参数名对应的反射上下文
        const paramValue = extractParamValue(pageParams, paramName) || 'REF';
        let ctx = null;
        if (snippetText.includes(paramValue)) {
            ctx = parseReflectionContext(snippetText, paramValue);
        }

        let pocs = [];
        if (ctx && ctx.exploitability > 0) {
            const generated = generatePocs(ctx, pageUrl, paramName);
            if (generated && generated.length > 0) {
                pocs = generated.map(p => p.url);
            }
        }

        // 兜底：如果 pocEngine 没生成，用 AI 自带的
        if (pocs.length === 0) {
            pocs = [
                ...(v.poc ? [v.poc] : []),
                ...(Array.isArray(v.pocs) ? v.pocs : []),
            ];
        }

        // 去重，最多 5 条
        const seen = new Set();
        const finalPocs = pocs.filter(p => { const k = p.trim(); if (!k || seen.has(k)) return false; seen.add(k); return true; }).slice(0, 5);

        return {
            ...v,
            poc: finalPocs[0] || v.poc || '',
            pocs: finalPocs,
        };
    });

    return { ...result, vulnerabilities: enriched };
}


function chromeTabsGet(tabId) {
    return new Promise((resolve) => {
        try {
            chrome.tabs.get(tabId, (tab) => {
                if (chrome.runtime.lastError) resolve(null);
                else resolve(tab || null);
            });
        } catch {
            resolve(null);
        }
    });
}

// Draw "N" icon, use native badge for number (reliable)
function setNIcon(tabId, count = 0) {
    // Best-effort: draw a simple N icon via OffscreenCanvas
    try {
        const size = 32;
        const canvas = new OffscreenCanvas(size, size);
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#6366f1';
        ctx.beginPath();
        ctx.roundRect(0, 0, size, size, 7);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 20px Arial, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('N', size / 2, size / 2 + 1);
        const imageData = ctx.getImageData(0, 0, size, size);
        chrome.action.setIcon({ imageData, tabId });
    } catch {}

    // Native badge
    if (count > 0) {
        const label = count > 99 ? '99+' : String(count);
        chrome.action.setBadgeText({ text: label, tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
    } else {
        chrome.action.setBadgeText({ text: '', tabId });
    }
}

// Smart code block extraction for large JS files
function extractKeyCodeBlocks(jsCode, { sources = [], sinks = [] }) {
    const blocks = [];
    let totalSize = 0;
    const maxBlockSize = 800; // chars per block
    const contextWindow = 150; // chars before/after match

    // Build regex patterns
    const sourcePattern = new RegExp(sources.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'gi');
    const sinkPattern = new RegExp(sinks.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'gi');

    // Find all matches
    const matches = [];
    let match;

    sourcePattern.lastIndex = 0;
    while ((match = sourcePattern.exec(jsCode)) !== null && matches.length < 50) {
        matches.push({ index: match.index, type: 'source', keyword: match[0] });
    }

    sinkPattern.lastIndex = 0;
    while ((match = sinkPattern.exec(jsCode)) !== null && matches.length < 50) {
        matches.push({ index: match.index, type: 'sink', keyword: match[0] });
    }

    // Sort by position
    matches.sort((a, b) => a.index - b.index);

    // Extract blocks with context
    const seen = new Set();
    for (const m of matches) {
        if (blocks.length >= 15) break; // max 15 blocks
        if (totalSize >= 12000) break; // max 12KB total

        const start = Math.max(0, m.index - contextWindow);
        const end = Math.min(jsCode.length, m.index + contextWindow);

        // Find function/block boundaries (simple heuristic)
        let blockStart = start;
        let blockEnd = end;

        // Expand to include full statements
        for (let i = start; i >= Math.max(0, start - 200); i--) {
            if (jsCode[i] === '\n' && (jsCode[i+1] === '\n' || /^(function|const|let|var|class|\})/i.test(jsCode.slice(i+1, i+20)))) {
                blockStart = i;
                break;
            }
        }
        for (let i = end; i < Math.min(jsCode.length, end + 200); i++) {
            if (jsCode[i] === '\n' && (jsCode[i+1] === '\n' || /^(function|const|let|var|class|\})/i.test(jsCode.slice(i+1, i+20)))) {
                blockEnd = i;
                break;
            }
        }

        let block = jsCode.slice(blockStart, blockEnd).trim();
        if (block.length > maxBlockSize) {
            block = block.slice(0, maxBlockSize) + '...';
        }

        const blockKey = `${blockStart}-${blockEnd}`;
        if (!seen.has(blockKey) && block.length > 30) {
            blocks.push(`// [${m.type.toUpperCase()}: ${m.keyword}]\n${block}`);
            seen.add(blockKey);
            totalSize += block.length;
        }
    }

    // If no matches found, take first and last chunks
    if (blocks.length === 0) {
        const firstChunk = jsCode.slice(0, 2000);
        const lastChunk = jsCode.slice(-2000);
        blocks.push(`// [FILE START]\n${firstChunk}`);
        if (jsCode.length > 4000) {
            blocks.push(`// [FILE END]\n${lastChunk}`);
        }
        totalSize = firstChunk.length + (jsCode.length > 4000 ? lastChunk.length : 0);
    }

    return { blocks, totalSize };
}

function getHighVulnCount(tabId) {
    return (tabVulnResults[tabId]?.vulnerabilities || []).filter(v => v.severity === 'high').length;
}

function updateHighVulnBadge(tabId) {
    // Always show current high-severity vuln count (real-time after analysis)
    const highVulnCount = getHighVulnCount(tabId);
    setNIcon(tabId, highVulnCount);
}

// 主动验证当前标签漏洞结果里的 XSS POC（哪条真弹窗），完成后刷新徽标。
// 默认开启（settings.pocVerify !== false），可在设置里关闭。
//
// 三态结果：
//   verified       → 弹窗了 ✓ 保持 HIGH
//   wafBlocked     → 被 WAF 拦 🛡️ 触发 AI 绕过 → 绕过成功 ✓ / 绕过失败 ⛔
//   falsePositive  → 误报 ✂️ 从结果中删除
async function verifyAndBadge(tabId, settings) {
    try {
        if (settings?.pocVerify === false) return;
        const res = tabVulnResults[tabId];
        if (!res || !Array.isArray(res.vulnerabilities) || res.vulnerabilities.length === 0) return;
        const hasXss = res.vulnerabilities.some(v => v?.type && v.type.toLowerCase().includes('xss'));
        if (!hasXss) return;

        if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
        tabAiStatus[tabId].verify = 'verifying';

        const { verifiedCount, wafBlockedVulns, falsePositives } = await verifyXssFindings(res.vulnerabilities);

        // 1. 误报 → 从结果中彻底移除
        if (falsePositives.length > 0) {
            const fpSet = new Set(falsePositives);
            res.vulnerabilities = res.vulnerabilities.filter(v => !fpSet.has(v));
        }

        // 2. WAF 拦截 → 尝试 AI 辅助绕过
        if (wafBlockedVulns.length > 0 && settings?.aiKey && settings?.aiAnalysis) {
            for (const v of wafBlockedVulns) {
                v.verdict = 'bypassing_ai'; // UI 显示"⏳ AI 绕过中"
                try {
                    const bypassSuccess = await aiWafBypass(tabId, v, res, settings);
                    if (bypassSuccess) {
                        verifiedCount++;
                        v.verified = true;
                        v.verdict = 'verified';
                        v.confidence = 0.98;
                        v.analysis = (v.analysis || '') + '\n\n✅ AI 辅助绕过 WAF 成功：生成的自定义 POC 已实测弹窗。';
                    } else {
                        v.verdict = 'bypass_failed';
                        v.analysis = (v.analysis || '') + '\n\n⛔ AI 辅助绕过失败：大模型生成的自定义绕过 POC 仍被 WAF 拦截或未触发弹窗。反射点确实存在但当前 WAF 防护较强。';
                    }
                } catch {
                    v.verdict = 'waf_blocked';
                    v.analysis = (v.analysis || '') + '\n\n🛡️ POC 均被 WAF 拦截，AI 绕过调用失败。';
                }
            }
        } else if (wafBlockedVulns.length > 0) {
            // 没配 AI，标记为 WAF 拦截但无法自动绕过
            for (const v of wafBlockedVulns) {
                v.verdict = 'waf_blocked';
                v.analysis = (v.analysis || '') + '\n\n🛡️ POC 均被 WAF 拦截。配置 AI API Key 可启用自动绕过尝试。';
            }
        }

        // 3. 对于标记为 bypass_failed 的，保持 HIGH 但降低置信度
        for (const v of res.vulnerabilities) {
            if (v.verdict === 'bypass_failed') {
                v.severity = 'high';
                v.confidence = 0.65;
            }
        }

        res.analyzedAt = Date.now();
        if (verifiedCount > 0) {
            res.summary = `${res.summary || ''}（${verifiedCount} 个已实测弹窗）`.replace(/^（/, '发现漏洞（');
        }
        tabAiStatus[tabId].verify = 'done';
        updateHighVulnBadge(tabId);
    } catch {
        if (tabAiStatus[tabId]) tabAiStatus[tabId].verify = 'done';
    }
}

// Only show badge after AI filter + vuln analysis completed
function updateHighVulnBadgeIfReady(tabId) {
    const st = tabAiStatus[tabId] || {};
    if (st.filter === 'done' && st.vuln === 'done') {
        updateHighVulnBadge(tabId);
    } else {
        setNIcon(tabId, 0);
    }
}

const tabHierarchies = {};
const tabScanResults = {};
const tabFilteredResults = {}; // tabId -> AI过滤后的结果
const tabVulnResults = {};     // tabId -> { vulnerabilities: [], summary: '', analyzedAt: ts }
const tabVulnTimers = {};      // debounce timers per tab
const tabFilterTimers = {};    // debounce timers for AI filter
const tabAiStatus = {};        // tabId -> { filter: 'idle'|'analyzing'|'done'|'error', vuln: 'idle'|'analyzing'|'done'|'error' }
const tabStaticXssTimers = {}; // debounce timers for static XSS detection

/**
 * AI 辅助 WAF 绕过：当本地绕过策略全部被 WAF 拦截时，
 * 将反射上下文 + 失败的 POC 发给 AI，让 AI 生成自定义绕过 payload 并尝试验证。
 * @returns {boolean} 是否绕过成功
 */
async function aiWafBypass(tabId, vuln, res, settings) {
    // 构造 bypass 上下文：从 tabScanResults 取 snippet
    const scan = tabScanResults[tabId] || {};
    const snippetText = [
        ...(scan.inlineScriptSnippet || []),
        ...(scan.inlineScriptProbeSnippet || []),
        ...(scan.inlineScriptSinkSnippet || []),
    ].slice(0, 3).join('\n---\n').slice(0, 2000);

    const promptPayload = {
        task: 'waf_bypass',
        pageUrl: res.pageUrl || '',
        vulnType: vuln.type || '',
        source: vuln.source || '',
        sink: vuln.sink || '',
        pocs: (Array.isArray(vuln.pocs) ? vuln.pocs : []).slice(0, 3),
        contextSnippet: snippetText,
    };

    try {
        const aiBypass = await callAI(
            settings.aiKey, settings.aiProvider || 'openai',
            settings.aiModel, settings.aiEndpoint,
            promptPayload, 'waf_bypass'
        );

        if (!aiBypass?.pocs || aiBypass.pocs.length === 0) return false;

        // 用 AI 生成的 payload 构造完整 POC URL
        const aiPocs = aiBypass.pocs.slice(0, 3);
        const aiPocUrls = [];
        const paramName = extractLikelyParamName(vuln, []) || 'message';

        for (const raw of aiPocs) {
            try {
                const u = new URL(res.pageUrl || vuln.pocs?.[0] || 'http://x/?x=1');
                if (u.searchParams.has(paramName)) {
                    u.searchParams.set(paramName, raw);
                } else {
                    // 如果 paramName 不对，尝试用第一个已有参数的 key
                    const keys = [...u.searchParams.keys()];
                    if (keys.length > 0) u.searchParams.set(keys[0], raw);
                    else u.searchParams.set('x', raw);
                }
                aiPocUrls.push(u.toString());
            } catch {}
        }

        if (aiPocUrls.length === 0) return false;

        // 导入验证器尝试 AI 生成的 POC
        const { verifyXssFindings } = await import('./pocVerifier');
        const testVuln = { ...vuln, pocs: aiPocUrls };
        const bypassResult = await verifyXssFindings([testVuln]);

        if (bypassResult.verifiedCount > 0) {
            vuln.verified = true;
            vuln.verifiedPocs = bypassResult.verifiedPocs || [];
            vuln.pocs = bypassResult.verifiedPocs || aiPocUrls;
            vuln.poc = (bypassResult.verifiedPocs || [])[0] || aiPocUrls[0];
            return true;
        }
        return false;
    } catch {
        return false;
    }
}

// Inline-script parameter reflection probe (lightweight, same-origin)
const tabProbeStatus = {};     // tabId -> { running?: boolean, done?: boolean, cacheKey?: string }

// LRU Cache with TTL for probe results
class ProbeCache {
    constructor(maxSize = 120, ttlMs = 30 * 60 * 1000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttlMs = ttlMs;
    }

    get(key) {
        const entry = this.cache.get(key);
        if (!entry) return null;

        // Check expiration
        if (Date.now() - entry.ts > this.ttlMs) {
            this.cache.delete(key);
            return null;
        }

        // LRU: move to end
        this.cache.delete(key);
        this.cache.set(key, entry);
        return entry;
    }

    set(key, value) {
        // Remove if exists (for LRU reordering)
        if (this.cache.has(key)) {
            this.cache.delete(key);
        }

        // Evict oldest if at capacity
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, { ...value, ts: Date.now() });
    }

    clear() {
        this.cache.clear();
    }

    get size() {
        return this.cache.size;
    }
}

const probeCache = new ProbeCache(120, 30 * 60 * 1000);

// Request deduplication: merge concurrent requests for same URL
const pendingProbeRequests = new Map(); // cacheKey -> Promise

// Auto AI filter after scan results settle (debounced, 5s)
async function autoAiFilter(tabId) {
    // Only run once per tab load (allow retry on error)
    const st = tabAiStatus[tabId]?.filter;
    if (st === 'analyzing' || st === 'done') return;

    const scanData = tabScanResults[tabId] || {};
    const total = Object.values(scanData).reduce((s, a) => s + a.length, 0);
    if (total === 0) return;

    const settings = await new Promise(r => chrome.storage.local.get('settings', d => r(d.settings || {})));
    if (!settings.aiKey || !settings.aiAnalysis) return;

    if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
    tabAiStatus[tabId].filter = 'analyzing';
    try {
        const result = await callAI(settings.aiKey, settings.aiProvider || 'openai', settings.aiModel, settings.aiEndpoint, scanData, 'filter');
        if (result && typeof result === 'object') {
            tabFilteredResults[tabId] = result;
            tabAiStatus[tabId].filter = 'done';
            updateHighVulnBadge(tabId);
        }
    } catch {
        tabAiStatus[tabId].filter = 'error';
    }
}

// Auto-run vuln analysis after JS files settle (debounced, 4s after last SCAN_RESULTS)
async function autoAnalyzeVulns(tabId, pageUrl) {
    // Only run once per tab load (allow retry on error)
    const st = tabAiStatus[tabId]?.vuln;
    if (st === 'analyzing' || st === 'done') return;

    const scanData = tabScanResults[tabId] || {};
    const jsFiles = scanData.jsFile || [];

    // NEW: reflected-XSS evidence collected by content script
    const pageParams = scanData.pageParamSample || [];
    const inlineSnippets = scanData.inlineScriptSnippet || [];
    const inlineSinkSnippets = scanData.inlineScriptSinkSnippet || [];
    const inlineProbeSnippets = scanData.inlineScriptProbeSnippet || [];
    const hasReflectedEvidence = pageParams.length > 0 && (inlineSnippets.length > 0 || inlineSinkSnippets.length > 0);

    // If no JS files and no reflected evidence, skip (keep old behavior)
    if (jsFiles.length === 0 && !hasReflectedEvidence) return;

    const settings = await new Promise(r => chrome.storage.local.get('settings', d => r(d.settings || {})));

    // 如果AI未配置，使用流水线检测（上下文分析 + POC 生成 + 验证）
    if (!settings.aiKey || !settings.aiAnalysis) {
        const pipelineResults = await runPipeline(scanData, pageUrl, settings);
        if (pipelineResults && pipelineResults.vulnerabilities.length > 0) {
            tabVulnResults[tabId] = pipelineResults;
            if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
            tabAiStatus[tabId].vuln = 'done';
            updateHighVulnBadge(tabId);
        }
        return;
    }

    // --- AI 路径（两段式：先跑本地流水线发现反射，需要时才发 JS 给 AI） ---

    // 第1步：运行本地流水线（0 token）
    // 从 pageParams + snippets 中发现反射点，做上下文分析，生成 POC
    const pipelineResults = await runPipeline(scanData, pageUrl, { pocVerify: false }); // 不在这步验证，最后统一验证
    const hasPipelineFindings = pipelineResults && pipelineResults.vulnerabilities.length > 0;

    // 第2步：如果有反射证据，走 Tier 1（廉价）——只发上下文 snippet 给 AI 确认
    // 不发整份 JS 文件，只发 ~200 字符的上下文片段
    if (hasPipelineFindings) {
        if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
        tabAiStatus[tabId].vuln = 'analyzing';

        const snippetText = buildContextSnippetForAI(pipelineResults.vulnerabilities, scanData);
        const aiConfirmPayload = {
            task: 'xss_validate',
            pageUrl,
            pageParams: scanData.pageParamSample || [],
            // 只发发现反射的 snippet 上下文，不 JS 内容
            reflectionContexts: snippetText,
            candidates: pipelineResults.vulnerabilities.map(v => ({
                type: v.type,
                param: v.source,
                sink: v.sink,
                poc: v.poc,
            })),
        };

        try {
            const aiResult = await callAI(settings.aiKey, settings.aiProvider || 'openai', settings.aiModel, settings.aiEndpoint, aiConfirmPayload, 'xss_validate');
            // AI 返回：哪些是真的 + 补充 POC
            if (aiResult?.vulnerabilities?.length > 0) {
                // AI 确认的用 AI 结果，AI 没提的保留 pipeline 结果
                const aiKeyed = new Map((aiResult.vulnerabilities || []).map(v => [`${v.source}|${v.sink}`.toLowerCase(), v]));
                for (const v of pipelineResults.vulnerabilities) {
                    const k = `${v.source}|${v.sink}`.toLowerCase();
                    const aiV = aiKeyed.get(k);
                    if (aiV) {
                        // AI 确认了：提升置信度，合并 POC
                        v.confidence = Math.max(v.confidence || 0, aiV.confidence || 0.7);
                        if (aiV.poc || Array.isArray(aiV.pocs)) {
                            const merged = new Set([...(Array.isArray(v.pocs) ? v.pocs : [v.poc].filter(Boolean)), ...(Array.isArray(aiV.pocs) ? aiV.pocs : [aiV.poc].filter(Boolean))]);
                            v.pocs = [...merged].slice(0, 5);
                            v.poc = v.pocs[0] || v.poc;
                        }
                    }
                    // AI 没提到但 pipeline 发现的：保持原样（置信度较低）
                }
                tabVulnResults[tabId] = { ...pipelineResults, vulnerabilities: pipelineResults.vulnerabilities, analyzedAt: Date.now() };
            } else {
                // AI 没确认任何，但 pipeline 有发现：保留 pipeline 结果
                tabVulnResults[tabId] = { ...pipelineResults, analyzedAt: Date.now() };
            }
        } catch {
            // AI 调用失败：保留 pipeline 结果
            tabVulnResults[tabId] = { ...pipelineResults, analyzedAt: Date.now() };
        }

        tabAiStatus[tabId].vuln = 'done';
        updateHighVulnBadge(tabId);
        await verifyAndBadge(tabId, settings);
        return;
    }

    // --- 第3步：没有反射证据，需要深度分析（成本高） ---
    // 下载 JS 文件发给 AI 做 source→sink 追踪，找 DOM XSS / Open Redirect / SSRF

    if (shouldProbeReflection(scanData, settings)) {
        try {
            await probeParamReflection(tabId, pageUrl, pageParams);
        } catch {}
    }

    const scanData2 = tabScanResults[tabId] || scanData;
    const inlineProbeSnippets2 = scanData2.inlineScriptProbeSnippet || [];
    // 第二次检查：probe 后有没有新增反射证据
    const hasProbeEvidence = (scanData2.inlineScriptProbeSnippet || []).length > 0;
    const hasSinkEvidence = (scanData2.inlineScriptSinkSnippet || []).length > 0;

    // 如果 probe 后发现了反射，用 pipeline + AI 快捷确认
    if (hasProbeEvidence) {
        const probePipeline = await runPipeline(scanData2, pageUrl, { pocVerify: false });
        if (probePipeline?.vulnerabilities?.length > 0) {
            tabVulnResults[tabId] = { ...probePipeline, analyzedAt: Date.now() };
            tabAiStatus[tabId].vuln = 'done';
            updateHighVulnBadge(tabId);
            await verifyAndBadge(tabId, settings);
            return;
        }
    }

    // 真的没有反射证据，且没有 sink 证据 → 跳过
    if (!hasSinkEvidence && !hasProbeEvidence && jsFiles.length === 0) {
        if (!tabVulnResults[tabId]) tabVulnResults[tabId] = { vulnerabilities: [], summary: '未发现明显反射证据', analyzedAt: Date.now() };
        return;
    }

    // --- Tier 2: 深度 JS 分析（仅当无反射证据时才执行，省 token） ---

    if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
    tabAiStatus[tabId].vuln = 'analyzing';
    const finalizeDeepNoFindings = (reason = '') => {
        tabAiStatus[tabId].vuln = 'done';
        if (!tabVulnResults[tabId]) tabVulnResults[tabId] = { vulnerabilities: [], summary: reason, analyzedAt: Date.now() };
        updateHighVulnBadge(tabId);
    };

    // Resolve relative URLs against pageUrl, filter third-party/CDN
    const jsUrls = jsFiles.map(u => {
        try { return new URL(u, pageUrl).href; } catch { return null; }
    }).filter(u => {
        if (!u) return false;
        try {
            if (/(jquery|bootstrap|lodash|vue\.min|react\.min|angular|gtm\.js|google-analytics|facebook|twitter\.com\/widgets|cdn\.|cloudflare|jsdelivr|unpkg)/i.test(u)) return false;
            return true;
        } catch { return false; }
    });
    const pageOrigin = new URL(pageUrl).origin;
    const sameOrigin = jsUrls.filter(u => u.startsWith(pageOrigin)).sort((a, b) => a.length - b.length);
    const crossOrigin = jsUrls.filter(u => !u.startsWith(pageOrigin)).sort((a, b) => a.length - b.length);
    const prioritized = [...sameOrigin, ...crossOrigin].slice(0, 5);

    const fetchOne = async (url) => {
        const r = await fetch(url, { credentials: 'omit', signal: AbortSignal.timeout(6000) });
        const text = await r.text();
        return { url, content: text, size: text.length };
    };

    let jsContents = [];
    try {
        const settled = await Promise.allSettled(prioritized.map(u => fetchOne(u)));
        jsContents = settled.filter(x => x.status === 'fulfilled').map(x => x.value);
    } catch {}

    // Smart extraction: extract key code blocks from large JS files
    jsContents = jsContents.map(js => {
        if (js.content.length <= 20000) {
            return { url: js.url, content: js.content, extracted: false };
        }

        // For large files: extract source/sink relevant code blocks
        const extracted = extractKeyCodeBlocks(js.content, {
            sources: ['location.search', 'location.hash', 'location.href', 'URLSearchParams', 'document.referrer', 'document.cookie', 'window.name', 'postMessage', 'addEventListener', '.value', 'localStorage', 'sessionStorage'],
            sinks: ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval', 'Function', 'setTimeout', 'setInterval', 'location.href', 'location.assign', 'location.replace', 'window.open', 'fetch', 'XMLHttpRequest', 'axios', 'WebSocket', '.html(', '.append(']
        });

        return {
            url: js.url,
            content: extracted.blocks.join('\n\n// --- [BLOCK SEPARATOR] ---\n\n'),
            extracted: true,
            originalSize: js.size,
            extractedSize: extracted.totalSize,
            blockCount: extracted.blocks.length
        };
    });

    // If we have neither JS nor reflected evidence, nothing to analyze
    if (jsContents.length === 0 && !hasReflectedEvidence) {
        finalizeDeepNoFindings('未能获取可分析的 JS 内容');
        return;
    }

    const combined = jsContents.map(x => x.content).join('\n');
    const sinkRe = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|contentDocument\.write|\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"][^'"]|setInterval\s*\(\s*['"][^'"]|location\.(href|assign|replace)\s*=|location\.(assign|replace)\s*\(|window\.open\s*\(|\bfetch\s*\(|XMLHttpRequest\s*\(|\.open\s*\(\s*['"]GET['"]|\baxios\s*\(|\$\.ajax\s*\(|WebSocket\s*\(|postMessage\s*\()/i;
    const sourceRe = /(location\.(search|hash|href)|URLSearchParams\s*\(|document\.(referrer|cookie)|window\.name|postMessage|addEventListener\(\s*['"]message['"]|localStorage\.|sessionStorage\.|\.value\b)/i;

    // If no reflected evidence, keep existing source/sink gate to avoid meaningless AI calls
    if (!hasReflectedEvidence) {
        if (!sinkRe.test(combined) && !sourceRe.test(combined)) {
            finalizeDeepNoFindings('未发现明显危险 source/sink，跳过 AI 分析');
            return;
        }
    }

    try {
        const payload = {
            jsContents: jsContents.map(js => ({
                url: js.url,
                content: js.content,
                extracted: js.extracted || false,
                originalSize: js.originalSize,
                blockCount: js.blockCount
            })),
            apis: scanData2.api || [],
            urls: scanData2.url || [],
            pageUrl,
            pageParams: scanData2.pageParamSample || [],
            inlineScriptSnippets: scanData2.inlineScriptSnippet || [],
            inlineScriptSinkSnippets: scanData2.inlineScriptSinkSnippet || [],
            inlineScriptProbeSnippets: inlineProbeSnippets2,
        };
        const resultRaw = await callAI(settings.aiKey, settings.aiProvider || 'openai', settings.aiModel, settings.aiEndpoint, payload, 'xss');
        const result = enrichReflectedXssPocs(resultRaw, { pageUrl, pageParams: payload.pageParams, inlineSnippets: [...(payload.inlineScriptSnippets || []), ...(payload.inlineScriptProbeSnippets || []), ...(payload.inlineScriptSinkSnippets || [])] });

        // Post-process: filter low confidence results and ensure GET-exploitable XSS
        if (result?.vulnerabilities?.length > 0) {
            result.vulnerabilities = result.vulnerabilities.filter(v => {
                // Keep high confidence or high severity
                if (v.confidence >= 0.7 || v.severity === 'high') return true;
                // For medium confidence, require detailed analysis
                if (v.confidence >= 0.5 && v.analysis && v.analysis.length > 50) return true;
                return false;
            }).filter(v => {
                // For XSS vulnerabilities, ensure they are GET-exploitable
                if (v.type?.toLowerCase().includes('xss')) {
                    // Check if POCs contain valid GET URLs
                    const allPocs = [
                        ...(Array.isArray(v.pocs) ? v.pocs : []),
                        ...(v.poc ? [v.poc] : [])
                    ];
                    // Must have at least one valid GET URL POC
                    const hasGetPoc = allPocs.some(poc => {
                        if (typeof poc !== 'string') return false;
                        // Check if it's a valid URL with query parameters
                        try {
                            const u = new URL(poc);
                            return u.search.length > 0; // Has query params = GET exploitable
                        } catch {
                            return false;
                        }
                    });
                    return hasGetPoc;
                }
                return true; // Non-XSS vulnerabilities pass through
            });
        }

        if (result?.vulnerabilities?.length > 0) {
            tabVulnResults[tabId] = { ...result, analyzedAt: Date.now() };
        } else {
            tabVulnResults[tabId] = { vulnerabilities: [], summary: result?.summary || '未发现可利用漏洞', analyzedAt: Date.now() };
        }

        // ❌ 不再合并静态检测结果。当 AI 配置且跑通时，AI 是唯一判断标准。
        // 静态检测只作为 AI 不可用/失败时的降级方案。
        // 原因：静态检测的误报率高（尤其 JS 字符串注入），合并会把 AI 已滤掉的假阳带回。
        // if (staticResults.vulnerabilities.length > 0) { ... }

        tabAiStatus[tabId].vuln = 'done';
        updateHighVulnBadge(tabId);

        // 主动验证 POC（实测哪条能弹窗，未验证通过的降为 LOW）
        await verifyAndBadge(tabId, settings);

        // 验证完成后再判断是否发通知（避免验证前的 highCount 不准确）
        const highVulnCount = getHighVulnCount(tabId);
        if (highVulnCount > 0) {
            const tab = await chromeTabsGet(tabId);
            let pageHost = '当前页面';
            try { if (tab?.url) pageHost = new URL(tab.url).hostname; } catch {}
            try {
                chrome.notifications.create(`vuln_${tabId}_${Date.now()}`, {
                    type: 'basic',
                    iconUrl: chrome.runtime.getURL('icons/icon128.png'),
                    title: `发现 ${highVulnCount} 个高危漏洞`,
                    message: `${pageHost} 存在可利用的高危漏洞，点击查看详情`,
                    priority: 2,
                });
            } catch {}
        }
    } catch {
        tabAiStatus[tabId].vuln = 'error';
        // AI失败时降级使用 pipeline 检测
        const fallbackResults = await runPipeline(scanData, pageUrl, settings);
        if (fallbackResults && fallbackResults.vulnerabilities.length > 0) {
            tabVulnResults[tabId] = fallbackResults;
            tabAiStatus[tabId].vuln = 'done';
            updateHighVulnBadge(tabId);
        }
    }
}

/**
 * 从 pipeline 结果中提取上下文片段传给 AI 做廉价确认（~200 tokens）。
 * 不传 JS 文件内容，只传反射点周围的 snippet。
 */
function buildContextSnippetForAI(vulnerabilities, scanData) {
    const allSnippets = [
        ...(scanData.inlineScriptSnippet || []),
        ...(scanData.inlineScriptSinkSnippet || []),
        ...(scanData.inlineScriptProbeSnippet || []),
    ];
    // 只取前 5 条最短的 snippet（足够确认，省 token）
    return allSnippets.sort((a, b) => a.length - b.length).slice(0, 5).join('\n---\n').slice(0, 2000);
}

// AI filter helper (exported for use by other modules)
export async function callAI(apiKey, provider, model, endpoint, data, task = 'filter') {
    const systemPrompts = {
        filter: `你是Web安全分析师。分析网页扫描结果，严格执行误报过滤：

1. credential（凭据/密钥）— 以下情况全部删除：
   - 值是UI提示文本（如”请输入密码”、”确认密码”、”重置密码”等）
   - 值含中文字符
   - 值是纯英文可读词组（如”ResetLoginPassword”、”ChangePassword”、”DefaultPassword”）
   - 值是变量名/属性名（如camelCase、snake_case，无数字和特殊字符）
   - 值是JS对象展开表达式（含”e.xxx”或多个逗号分隔属性）
   - 值是云服务名称（如”Alicloud”、”Registration”）
   - 值长度小于12且不含数字或特殊字符
   - authorization字段值是代码片段而非真实token
   只保留：看起来是真实随机密钥/token的值（含随机字符、数字混合，长度>=16，或符合已知密钥格式）

2. absoluteApi/api: 去重，移除混淆变量名、CSS类名、无意义短字符串，保留真实API路径。
3. ip: 移除内网/保留地址误报，保留真实公网IP。
4. 其他分类: 移除明显误报和重复项。

只返回JSON对象，结构与输入相同，不要任何额外文字。`,
        xss_validate: `你是XSS漏洞确认专家。你的任务不是"发现"漏洞，而是"验证"本地引擎发现的候选漏洞。

输入已经包含：
- candidates：本地检测引擎发现的候选漏洞（含类型、参数名、sink）
- reflectionContexts：反射点的HTML/JS上下文片段

你的工作：
1. 检查每个candidate的上下文是否真的可利用
2. 如果上下文被正确转义（HTML实体/JS转义/JSON.stringify），标记为不可用
3. 如果参数值在JSON键位置("key":)或注释中，标记为不可用
4. 如果确实可利用，输出confidence和更好的POC（可选）

输出格式（JSON数组，每个元素一条确认的漏洞）：
[
  {
    "source": "URL parameter: xxx",
    "sink": "JavaScript string literal",
    "confidence": 0.85,
    "analysis": "确认原因",
    "poc": "完整的POC URL或payload",
    "pocs": ["备用POC"]
  }
]

如果全部不可用，输出空数组 []。
不要输出任何额外文字，只输出JSON。`,
    waf_bypass: `你是一个XSS WAF绕过专家。你的任务是在本地绕过策略全部被WAF拦截时，生成能够突破该WAF的自定义payload。

输入包含：
- vulnType: 漏洞类型
- source: 参数名
- sink: 危险点（如 JavaScript string literal / HTML body / innerHTML）
- pocs: 已被 WAF 拦截的失败 POC URL 列表（供你分析 WAF 拦截了什么特征）
- contextSnippet: 反射点周围的 HTML/JS 代码片段

你的工作：
1. 分析失败 POC 中被 WAF 拦截的特征（关键字、特殊字符模式）
2. 结合 contextSnippet 判断反射点的精确上下文
3. 生成 1-3 条绕过 WAF 的自定义 payload（不做 URL 编码，只给原始 payload 字符串）

绕过策略参考（不限于此）：
- 大小写混淆：OnErRoR、OnLoAd、Javascript
- HTML 实体编码：&#97;lert、&#106;avascript
- Unicode 转义（仅在 JS 字符串上下文）：\\u0061lert
- 标签复用：<img src=x onerror=> 用 autofocus + onfocus 代替
- 事件替换：onerror → onfocus、ontoggle、onmouseover
- 关键字拆分：top[/al/.source+/ert/.source]、window['al'+'ert']
- eval + base64：eval(atob('base64编码的alert(1)'))
- 注释绕过：al/**/ert(1)
- 使用 confirm 或 prompt 代替 alert
- ⭐ silent marker 绕过（推荐）：document.title='__NOTHING_POC__';document.cookie='__NOTHING_POC=1'  （WAF 从不拦这个，所有 payload 优先附带）

只输出JSON（不要任何额外文字），格式：
{
  "pocs": ["第一条payload", "第二条payload", "第三条payload"]
}`,
        xss: `你是资深渗透测试工程师，专注前端安全漏洞挖掘。

请基于输入的数据（可能包含 JS 源码 + 页面 URL 参数样本 + 内联脚本片段），尽可能从代码/脚本层面挖掘以下类型的”可利用”漏洞，并给出可复现的测试 POC：
- Reflected XSS（服务端反射型：query 参数进入页面内联 <script>，导致 JS 字符串注入/拼接执行）
- DOM XSS（重点）
- 任意 URL 跳转 / Open Redirect
- SSRF（前端侧：客户端可控 URL 被用于发起请求，可能导致内网探测/云元数据访问等）

【输入字段说明】
- pageUrl：当前页面完整 URL（包含 query）
- pageParams：采样到的 query 参数 key=value（已解码、截断；形如 “PARAM: k=v”）
- inlineScriptSnippets：强证据：当前页面中命中”参数 key/value”的内联脚本窗口片段（截断；形如 “INLINE_SCRIPT_SNIPPET ...”）
- inlineScriptProbeSnippets：强证据（探针命中）：后台对同路径做少量 marker GET 探测后，发现 marker 出现在返回 HTML 的内联 <script> 中的窗口片段（截断；形如 “INLINE_SCRIPT_PROBE_SNIPPET (param=..., marker=...) ...”）
- inlineScriptSinkSnippets：弱证据：未命中反射值时采集的内联脚本 sink 周边片段（截断；形如 “INLINE_SCRIPT_SINK_SNIPPET ...”）
- jsContents：JS 文件数组，每个包含：
  * url：JS 文件 URL
  * content：JS 代码内容（可能是智能提取的关键代码块）
  * extracted：是否为智能提取（true 表示从大文件中提取了 source/sink 相关代码块）
  * originalSize：原始文件大小（字节）
  * blockCount：提取的代码块数量

【重要】当 extracted=true 时，content 包含多个代码块，每个块以 “// [SOURCE: xxx]” 或 “// [SINK: xxx]” 开头，表示该块包含对应的污点源或危险汇聚点。请重点分析这些标记的代码块之间的数据流关系。

【Reflected XSS 判断标准（务必严格）】
只有当你能从 inlineScriptSnippets 或 inlineScriptProbeSnippets 推断：攻击者可控的 query 参数值进入了 JS/脚本上下文（尤其是字符串字面量/拼接），且未做正确的 JS 字符串转义/编码，导致可闭合引号并注入语句或表达式时，才输出 Reflected XSS。

【严格排除以下情况（常见误报模式）】
1. 参数值只出现在 HTML 文本/DOM 属性中，未进入 JS 上下文
2. 明显做了安全转义：JSON.stringify()、正确的 escapeHtml/escapeJs、encodeURIComponent 等
3. 参数值被用作数组索引、对象 key、数值运算等非字符串上下文
4. 只有 inlineScriptSinkSnippets（弱证据），没有任何反射/探针命中证据
5. 参数值出现在注释、字符串字面量定义（非拼接）、正则表达式字面量中
6. 框架自动转义：React/Vue/Angular 的模板绑定、v-text、textContent 等

【置信度评估】
对每个漏洞输出 confidence 字段（0.0-1.0）：
- 1.0：有明确 probe 命中 + 无转义 + 可闭合引号
- 0.8-0.9：有 snippet 命中 + 上下文清晰 + 可利用
- 0.6-0.7：有弱证据 + 推测可能存在（需人工验证）
- <0.6：不应输出（证据不足）

【POC 输出要求（质量 > 数量：先给一条能真正打的）】
- 每个漏洞输出 poc（唯一主推荐，必须是最可能绕过 WAF 且上下文精确闭合的那一条）、pocs（最多 3 条，主 POC + 至多 2 条不同手法的兜底）、confidence。
- **精确闭合上下文**：先根据 snippet 判断反射点被什么包裹——引号类型（" / ' / \`）、是否在对象/数组/函数调用内。据此逐字构造闭合序列，例如：
  * 普通字符串赋值 var x="REF"     → 用  ";<payload>;//
  * 对象取值 {k:"REF"}            → 用  "}<payload>,{//   （先闭合对象再重开吞尾，如已验证可用的 "}a=\\u0061lert,a\`1\`,{//）
  * 模板字符串 \`...REF...\`        → 用  \${alert(1)} 或闭合反引号
  不要给闭合方式和实际上下文不符的 payload（那样只会报错/被拦，等于误报）。
- **主 POC 默认采用 WAF 绕过组合**：\\uXXXX 混淆关键字（\\u0061lert）+ tagged template 免括号调用（a\`1\`），避免明文 "alert"、"(" 被规则命中。
- 必须是 GET 可直接访问的完整 URL，payload 部分 URL 编码。只输出 GET 可利用的 XSS，POST/其它方法不输出。
- 宁缺毋滥：给不出能真正闭合并执行的 POC，就不要输出该漏洞。

【第一步：识别污点源（source）】
以下均视为攻击者可控（无需以”难控制”为由排除）：
- location.search / location.hash / location.href / document.URL
- URLSearchParams.get()
- document.referrer
- window.name
- postMessage event.data
- DOM 输入：input/textarea/select 的 .value（含 querySelector/getElementById 获取）
- localStorage/sessionStorage 中读取的值（若可被同站点任意脚本写入，也可被攻击者影响）

【第二步：追踪到危险汇聚点（sink）】
1) DOM XSS sinks：
- innerHTML / outerHTML
- insertAdjacentHTML
- document.write / document.writeln / iframe.contentDocument.write
- eval / new Function / setTimeout(string) / setInterval(string)
- jQuery: .html() / .append() / .prepend() / .after() / .before()

2) Open Redirect sinks：
- location.href = ... / location.assign(...) / location.replace(...)
- window.open(url)

3) SSRF sinks（客户端可控 URL 用于发起请求）：
- fetch(url)
- new XMLHttpRequest().open(method, url)
- axios(url) / $.ajax({ url }) / $.get(url) / $.post(url)
- WebSocket(url)

【第三步：可利用性判断（必须输出”可利用”的）】
只有当你能确认攻击者可控 source 最终影响 sink，且中间缺少有效限制/过滤（白名单、URL 解析校验、域名限制等）时才输出。
- 对 Open Redirect：需能构造跳转到任意外部域名的 URL（非仅站内跳转）
- 对 SSRF：需能构造请求到攻击者指定地址（至少可控协议/主机/路径之一）。若代码存在域名白名单/同源强约束，请不要输出。

【第四步：数据流分析（针对智能提取的代码块）】
当 jsContents[].extracted=true 时：
1. 识别所有标记为 [SOURCE: xxx] 的代码块，提取变量名
2. 识别所有标记为 [SINK: xxx] 的代码块，提取变量名
3. 分析变量之间的赋值、传递、函数调用关系
4. 构建完整的污点传播链：source变量 → 中间变量 → sink变量
5. 检查传播链中是否存在过滤/转义/验证逻辑

【第五步：输出要求】
对每个漏洞必须包含：
- type：漏洞类型
- severity：严重程度（high/medium/low）
- confidence：置信度（0.0-1.0）
- file：漏洞所在 JS 文件 URL；若为 Reflected XSS 可填 pageUrl 或 “inline-script”
- source / sink：关键代码片段（Reflected XSS 的 source 建议写明参数名，如 “message=”；sink 引用 snippet 中的赋值/拼接片段）
- chain：完整传播链（source → 中间变量 → sink）
- analysis：你是如何判断可利用（约束条件/绕过点/为何无过滤/为何置信度高）
- description：漏洞说明及利用条件
- poc：可直接复制测试的**主** POC（Reflected XSS 必须给出完整 GET 请求 URL，payload 建议 URL 编码，且上下文精确闭合 + 默认 WAF 绕过手法）
- pocs：POC 列表（最多 3 条字符串数组，主 POC + 至多 2 条不同手法兜底，Reflected XSS 必须是 GET 请求 URL）

返回 JSON（无漏洞则 vulnerabilities 为空数组）：
{“vulnerabilities”: [{“type”: “DOM XSS|Reflected XSS|Open Redirect|SSRF”, “severity”: “high|medium|low”, “confidence”: 0.95, “file”: “JS文件URL或pageUrl”, “source”: “source代码”, “sink”: “sink代码”, “chain”: “source → ... → sink”, “analysis”: “分析过程”, “description”: “漏洞说明及利用条件”, “poc”: “可用POC”, “pocs”: [“poc1”, “poc2”, “poc3”, “poc4”, “poc5”]}], “summary”: “总结”}
只返回 JSON，不要任何额外文字。`,
        backup_filter: `你是Web安全专家，负责过滤备份文件扫描的误报。

【输入格式】
findings 数组，每个元素包含：
- url: 完整 URL
- path: 路径
- type: 类型（vcs/sensitive/backup）
- status: HTTP 状态码
- size: 文件大小（字节）
- contentType: Content-Type
- contentPreview: 内容预览（前 2KB）

【任务】
分析每个 finding 的 contentPreview，判断是否为真实的敏感文件泄露。

【严格排除以下误报（必须删除）】
1. **404/错误页面**：
   - 包含 “404”, “Not Found”, “File Not Found”, “Page Not Found”
   - 包含 “Error Page”, “Error Occurred”, “Unexpected Error”
   - 包含 “Whitelabel Error Page”
   - 包含 “No mapping for”, “No static resource”
   - 包含 “Access Denied”, “Forbidden”, “Unauthorized”
   - Spring Boot/Nginx/Apache 错误页面

2. **HTML 错误页面**：
   - 包含 <!DOCTYPE html> 且内容提到 error/404/exception
   - 包含 <title>Error</title> 或类似标题

3. **空文件或无效内容**：
   - contentPreview 为空或只有空白字符
   - 文件大小 < 100 字节且不是有效格式

4. **框架默认页面**：
   - Spring Boot 默认错误页
   - Nginx/Apache 默认页面
   - Tomcat 默认页面

【保留以下真实泄露（必须保留）】
1. **版本控制文件**：
   - SVN: 包含 “svn:” 或 SQLite 格式
   - Mercurial: 包含 “revlogv1”, “store”, “fncache”
   - CVS: 包含 CVS entries 格式

2. **配置文件**：
   - .env: 包含 KEY=value 格式的环境变量
   - PHP 配置: 包含 <?php 代码
   - JSON 配置: 有效的 JSON 格式
   - YAML 配置: 有效的 YAML 格式

3. **备份文件**：
   - 压缩文件: contentPreview 包含 "50 4b 03 04" (ZIP), "52 61 72 21" (RAR), "1f 8b" (GZIP), "37 7a" (7z) 等文件头
   - SQL 备份: 包含 CREATE TABLE, INSERT INTO 等 SQL 语句
   - 文件大小 > 10KB 且不是 HTML
   - contentPreview 包含 "[Binary file, header:" 说明是真实的二进制文件

4. **敏感文件**：
   - 日志文件: 包含时间戳和日志级别
   - Docker 文件: 包含 FROM, RUN, CMD 等指令
   - 部署脚本: 包含 shell/bash 脚本内容

【输出格式】
返回 JSON：
{
  “valid”: [“url1”, “url2”, ...],  // 真实泄露的 URL 列表
  “rejected”: {                     // 被拒绝的 URL 及原因
    “url3”: “404 错误页面”,
    “url4”: “Spring Boot 错误页”
  }
}

只返回 JSON，不要任何额外文字。`
    }

    const system = systemPrompts[task] || systemPrompts.filter

    // Truncate data to avoid context overflow
    let payload = data
    if (task === 'filter') {
        // For filter task: cap each category at 80 items, each item at 200 chars
        payload = {}
        for (const [cat, items] of Object.entries(data)) {
            if (!Array.isArray(items)) { payload[cat] = items; continue; }
            payload[cat] = items.slice(0, 80).map(v =>
                typeof v === 'string' && v.length > 200 ? v.slice(0, 200) + '…' : v
            )
        }
    }
    if (task === 'xss') {
        // For vuln analysis: smart truncation with metadata
        payload = { ...data }
        if (Array.isArray(payload.jsContents)) {
            payload.jsContents = payload.jsContents.slice(0, 3).map(x => ({
                url: x.url,
                content: (x.content || '').slice(0, 10000), // increased from 6000 to 10000
                extracted: x.extracted,
                originalSize: x.originalSize,
                blockCount: x.blockCount
            }))
        }
        if (Array.isArray(payload.apis)) payload.apis = payload.apis.slice(0, 80)
        if (Array.isArray(payload.urls)) payload.urls = payload.urls.slice(0, 80)

        // NEW: keep reflected-XSS evidence small
        if (Array.isArray(payload.pageParams)) {
            payload.pageParams = payload.pageParams.slice(0, 20).map(v =>
                typeof v === 'string' && v.length > 300 ? v.slice(0, 300) + '…' : v
            )
        }
        if (Array.isArray(payload.inlineScriptSnippets)) {
            payload.inlineScriptSnippets = payload.inlineScriptSnippets.slice(0, 5).map(s =>
                typeof s === 'string' && s.length > 1200 ? s.slice(0, 1200) + '…' : s
            )
        }
        if (Array.isArray(payload.inlineScriptProbeSnippets)) {
            payload.inlineScriptProbeSnippets = payload.inlineScriptProbeSnippets.slice(0, 5).map(s =>
                typeof s === 'string' && s.length > 1200 ? s.slice(0, 1200) + '…' : s
            )
        }
        if (Array.isArray(payload.inlineScriptSinkSnippets)) {
            payload.inlineScriptSinkSnippets = payload.inlineScriptSinkSnippets.slice(0, 3).map(s =>
                typeof s === 'string' && s.length > 1200 ? s.slice(0, 1200) + '…' : s
            )
        }
    }
    if (task === 'backup_filter') {
        // For backup filter: limit findings and content preview
        payload = { ...data }
        if (Array.isArray(payload.findings)) {
            payload.findings = payload.findings.slice(0, 20).map(f => ({
                url: f.url,
                path: f.path,
                type: f.type,
                status: f.status,
                size: f.size,
                contentType: f.contentType,
                contentPreview: (f.contentPreview || '').slice(0, 2000)
            }))
        }
    }
    const body_common = JSON.stringify(payload)

    const providerCfg = getProvider(provider)
    const url = resolveAiUrl(provider, endpoint)

    // Anthropic-style (Messages API) — direct or via proxy
    if (providerCfg.style === 'anthropic') {
        const r = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: model || providerCfg.defaultModel,
                max_tokens: 8192,
                system,
                messages: [{ role: 'user', content: body_common }]
            })
        })
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text().catch(() => '')}`)
        const j = await r.json()
        const text = j.content?.[0]?.text || ''
        const jsonMatch = text.match(/```json\n?([\s\S]*?)\n?```/) || text.match(/(\{[\s\S]*\}|\[[\s\S]*\])/)
        return JSON.parse(jsonMatch ? jsonMatch[1] || jsonMatch[0] : text)
    }

    // OpenAI-compatible (OpenAI / DeepSeek / 智谱GLM / custom proxy)
    const r = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
            model: model || providerCfg.defaultModel || 'gpt-4o-mini',
            response_format: { type: 'json_object' },
            messages: [
                { role: 'system', content: system },
                { role: 'user', content: body_common }
            ]
        })
    })
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text().catch(() => '')}`)
    const j = await r.json()
    const content = j.choices?.[0]?.message?.content || ''
    // Some OpenAI-compatible models wrap JSON in ```json fences even in json mode.
    const fence = content.match(/```json\n?([\s\S]*?)\n?```/) || content.match(/(\{[\s\S]*\}|\[[\s\S]*\])/)
    return JSON.parse(fence ? fence[1] || fence[0] : content)
}

// Tab lifecycle
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading') {
        delete tabScanResults[tabId];
        delete tabFilteredResults[tabId];
        delete tabFingerprints[tabId];
        delete tabJsMap[tabId];
        delete tabVulnResults[tabId];
        delete tabAiStatus[tabId];
        delete tabProbeStatus[tabId];
        clearTimeout(tabVulnTimers[tabId]);
        clearTimeout(tabFilterTimers[tabId]);
        clearTimeout(tabStaticXssTimers[tabId]);
        // Pass current tab hostname so globalScannedPaths is cleared correctly
        let navHostname = null;
        try { if (tab.url) navHostname = new URL(tab.url).hostname; } catch {}
        activeScanner.reset(tabId, navHostname);
        backupScanner.reset(tabId);
        ruleEngine.resetHistory();
        setNIcon(tabId, 0);
    }
    if (changeInfo.status === 'complete' && tab.url) {
        if (tab.url.startsWith('http')) {
            const hierarchies = getParentHierarchies(tab.url);
            tabHierarchies[tabId] = hierarchies;
            ruleEngine.match(tab.url, 'url', { tabId, url: tab.url });
            hierarchies.forEach(h => ruleEngine.match(h, 'url', { tabId, url: h }));
            activeScanner.scan(tab.url, tabId);
            backupScanner.scan(tab.url, tabId);
        }
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabHierarchies[tabId];
    delete tabScanResults[tabId];
    delete tabFilteredResults[tabId];
    delete tabFingerprints[tabId];
    delete tabJsMap[tabId];
    delete tabVulnResults[tabId];
    delete tabAiStatus[tabId];
    delete tabProbeStatus[tabId];
    clearTimeout(tabVulnTimers[tabId]);
    clearTimeout(tabFilterTimers[tabId]);
    clearTimeout(tabStaticXssTimers[tabId]);
    delete tabVulnTimers[tabId];
    delete tabFilterTimers[tabId];
    delete tabStaticXssTimers[tabId];
});

// Message router
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const tabId = sender.tab?.id ?? request.tabId;

    if (request.action === 'SCAN_RESULTS') {
        if (tabId) {
            if (!tabScanResults[tabId]) tabScanResults[tabId] = {};
            for (const [cat, items] of Object.entries(request.data || {})) {
                if (!tabScanResults[tabId][cat]) tabScanResults[tabId][cat] = [];
                const existing = new Set(tabScanResults[tabId][cat]);
                for (const item of items) existing.add(item);
                tabScanResults[tabId][cat] = [...existing];
            }
            const total = Object.values(tabScanResults[tabId]).reduce((s, a) => s + a.length, 0);
            // During scanning/AI stages, do not show counts; only show after AI done
            updateHighVulnBadgeIfReady(tabId);
            // Debounce auto vuln analysis: trigger 4s after last SCAN_RESULTS for this tab
            const hasVulnTriggerData =
                (tabScanResults[tabId].jsFile?.length > 0) ||
                (tabScanResults[tabId].inlineScriptSnippet?.length > 0) ||
                (tabScanResults[tabId].pageParamSample?.length > 0);
            if (hasVulnTriggerData && request.url) {
                if (!tabAiStatus[tabId]?.vuln) {
                    clearTimeout(tabVulnTimers[tabId]);
                    tabVulnTimers[tabId] = setTimeout(() => autoAnalyzeVulns(tabId, request.url), 4000);
                }
            }

            // 静态XSS检测：在AI关闭时触发
            const hasXssEvidence =
                (tabScanResults[tabId].pageParamSample?.length > 0) &&
                (tabScanResults[tabId].inlineScriptSnippet?.length > 0 ||
                 tabScanResults[tabId].inlineScriptSinkSnippet?.length > 0);

            if (hasXssEvidence && request.url) {
                clearTimeout(tabStaticXssTimers[tabId]);
                tabStaticXssTimers[tabId] = setTimeout(async () => {
                    const settings = await chrome.storage.local.get('settings');
                    // 只在AI关闭时执行静态检测
                    if (!settings.settings?.aiAnalysis || !settings.settings?.aiKey) {
                        const result = staticXssDetector.analyze(tabScanResults[tabId], request.url);
                        if (result.vulnerabilities.length > 0) {
                            tabVulnResults[tabId] = result;
                            if (!tabAiStatus[tabId]) tabAiStatus[tabId] = {};
                            tabAiStatus[tabId].vuln = 'done';
                            updateHighVulnBadge(tabId);
                        }
                    }
                }, 2000);
            }
            // Debounce auto AI filter: trigger 5s after last SCAN_RESULTS for this tab
            if (!tabAiStatus[tabId]?.filter) {
                clearTimeout(tabFilterTimers[tabId]);
                tabFilterTimers[tabId] = setTimeout(() => autoAiFilter(tabId), 5000);
            }
        }
        sendResponse({ ok: true });
        return true;
    }

    if (request.action === 'GET_SCAN_RESULTS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ data: tid ? (tabFilteredResults[tid] || tabScanResults[tid] || {}) : {} });
        });
        return true;
    }

    if (request.action === 'GET_VULN_RESULTS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ data: tid ? (tabVulnResults[tid] || null) : null });
        });
        return true;
    }

    if (request.action === 'GET_AI_STATUS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ status: tid ? (tabAiStatus[tid] || {}) : {} });
        });
        return true;
    }

    if (request.action === 'GET_FINGERPRINTS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ data: tid ? (tabFingerprints[tid] || {}) : {} });
        });
        return true;
    }

    if (request.action === 'GET_SITE_ANALYSIS') {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            const url = tabs[0]?.url;
            if (!url || !url.startsWith('http')) {
                sendResponse({ error: 'No active HTTP tab' });
                return;
            }
            try {
                const urlObj = new URL(url);
                const hostname = urlObj.hostname;
                const protocol = urlObj.protocol;

                // Internal / intranet targets have no public ICP or geo info — don't
                // fire (failing) public lookups, just report a clean internal state.
                if (isInternalHost(hostname)) {
                    sendResponse({
                        hostname, protocol, isInternal: true,
                        resolvedIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? hostname : null,
                    });
                    return;
                }

                // 直接用域名查IP，跳过国内无法访问的 Google DoH
                const [icp, ipInfo] = await Promise.all([
                    queryICP(hostname),
                    queryIPInfo(hostname),
                ]);
                const resolvedIp = ipInfo?.data?.ip || null;
                sendResponse({ icp, ip: ipInfo, hostname, resolvedIp, protocol });
            } catch (e) {
                sendResponse({ error: e.message });
            }
        });
        return true;
    }

    if (request.action === 'GET_SETTINGS') {
        chrome.storage.local.get('settings', (data) => {
            sendResponse({ settings: data.settings || {} });
        });
        return true;
    }

    if (request.action === 'GET_BACKUP_FINDINGS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ findings: tid ? backupScanner.getFindings(tid) : [] });
        });
        return true;
    }

    if (request.action === 'GET_BACKUP_STATUS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tid = tabs[0]?.id;
            sendResponse({ status: tid ? backupScanner.getStatus(tid) : null });
        });
        return true;
    }

    if (request.action === 'CLEAR_BACKUP_CACHE') {
        backupScanner.clearCache();
        sendResponse({ ok: true });
        return true;
    }

    if (request.action === 'SET_SETTING') {
        chrome.storage.local.get('settings', (data) => {
            const settings = data.settings || {};
            settings[request.key] = request.value;
            chrome.storage.local.set({ settings }, () => sendResponse({ ok: true }));
        });
        return true;
    }

    if (request.action === 'SET_SETTINGS_BULK') {
        chrome.storage.local.get('settings', (data) => {
            const settings = { ...(data.settings || {}), ...request.values };
            chrome.storage.local.set({ settings }, () => sendResponse({ ok: true }));
        });
        return true;
    }

    if (request.action === 'AI_FILTER') {
        chrome.storage.local.get('settings', async (data) => {
            const s = data.settings || {};
            if (!s.aiKey) { sendResponse({ error: '未配置 AI API Key，请在设置中填写' }); return; }
            try {
                const result = await callAI(s.aiKey, s.aiProvider || 'openai', s.aiModel, s.aiEndpoint, request.data, 'filter');
                sendResponse({ data: result });
            } catch (e) {
                sendResponse({ error: e.message });
            }
        });
        return true;
    }

    if (request.action === 'AI_XSS_ANALYZE') {
        chrome.storage.local.get('settings', async (data) => {
            const s = data.settings || {};
            if (!s.aiKey) { sendResponse({ error: '未配置 AI API Key' }); return; }
            try {
                // Fetch actual JS content for analysis (up to 5 files, skip CDN/third-party)
                const jsUrls = (request.data.jsFiles || []).filter(u => {
                    try {
                        const h = new URL(u).hostname;
                        return !/(cdn|static|jquery|bootstrap|lodash|vue|react|angular|gtm|google|facebook|twitter|baidu)/i.test(h);
                    } catch { return false; }
                }).slice(0, 5);

                const jsContents = [];
                for (const url of jsUrls) {
                    try {
                        const r = await fetch(url, { credentials: 'omit', signal: AbortSignal.timeout(5000) });
                        const text = await r.text();
                        // Only send first 8000 chars per file to avoid token overflow
                        jsContents.push({ url, content: text.slice(0, 8000) });
                    } catch {}
                }

                const payload = {
                    jsContents,
                    apis: request.data.apis || [],
                    urls: request.data.urls || [],
                    pageUrl: request.data.pageUrl || ''
                };

                const result = await callAI(s.aiKey, s.aiProvider || 'openai', s.aiModel, s.aiEndpoint, payload, 'xss');
                sendResponse({ data: result });
            } catch (e) {
                sendResponse({ error: e.message });
            }
        });
        return true;
    }

    if (request.action === 'AI_SUGGEST_RULES') {
        // AI_SUGGEST_RULES removed - no longer supported
        sendResponse({ error: 'AI推荐功能已移除' });
        return true;
    }

    if (request.action === 'FETCH_JS') {
        const tabId = sender?.tab?.id;
        // Fallback: fetch from the page context WITH the page's cookies. Needed for
        // auth-gated JS (the SW's credential-less fetch gets 302-redirected to a login
        // page and returns that HTML, which looks "successful" but isn't the JS).
        const viaPage = async () => {
            if (tabId == null || !chrome.scripting) return null;
            try {
                const [res] = await chrome.scripting.executeScript({
                    target: { tabId },
                    func: (u) => fetch(u, { credentials: 'include' })
                        .then(r => (r.ok && !r.redirected && !/text\/html/i.test(r.headers.get('content-type') || '')) ? r.text() : null)
                        .catch(() => null),
                    args: [request.url],
                });
                return res?.result ?? null;
            } catch (e) { return null; }
        };
        const looksLikeJs = (r, text) => {
            const ct = r.headers.get('content-type') || '';
            if (/text\/html/i.test(ct)) return false;
            // A redirected response or an HTML doc body means we got a login/redirect page.
            if (/^\s*<(?:!doctype|html)/i.test(text)) return false;
            return true;
        };
        fetch(request.url, { credentials: 'omit', redirect: 'follow' })
            .then(async r => {
                if (!r.ok || r.redirected) return await viaPage();
                const text = await r.text();
                return looksLikeJs(r, text) ? text : await viaPage();
            })
            .then(content => sendResponse({ content }))
            .catch(async () => sendResponse({ content: await viaPage() }));
        return true;
    }

    if (request.action === 'testNotification') {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon128.png'),
            title: 'Nothing Extension',
            message: 'Test notification successful!',
        }, (id) => {
            if (chrome.runtime.lastError) {
                sendResponse({ success: false, error: chrome.runtime.lastError.message });
            } else {
                sendResponse({ success: true, id });
            }
        });
        return true;
    }
});

chrome.runtime.onInstalled.addListener(() => {
    console.log('Nothing extension installed');
    setupOffscreenDocument('src/offscreen/offscreen.html');
    // Load WAF strategy scores from storage
    wafStrategy.load();
    // Set default N icon for all tabs
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => { if (tab.id) setNIcon(tab.id, 0); });
    });
});

let creating;
async function setupOffscreenDocument(path) {
    const existingContexts = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
        documentUrls: [chrome.runtime.getURL(path)],
    });
    if (existingContexts.length > 0) return;
    if (creating) {
        await creating;
    } else {
        creating = chrome.offscreen.createDocument({
            url: path,
            reasons: ['AUDIO_PLAYBACK'],
            justification: 'Notification sound for rule matches',
        });
        await creating;
        creating = null;
    }
}
