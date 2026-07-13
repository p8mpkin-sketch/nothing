/**
 * 主动 POC 验证器
 *
 * 在后台标签逐条加载候选 POC，配合 document_start 注入的 MAIN world alert hook，
 * 检测 payload 是否真的执行。只有实测弹窗的 POC 才标记为已验证。
 *
 * 增强：
 * - 验证结果反馈给 WAF 策略管理器（记录哪些绕过策略有效）
 * - 失败时分析页面状态（500 / WAF 拦截 / 404）
 */

import { wafStrategy } from './pocEngine';

const HOOK_ID = 'nothing-poc-alert-hook';
const HOOK_FILE = 'poc-hook.js';

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function tabsCreate(opts) {
    return new Promise(res => { try { chrome.tabs.create(opts, t => res(t || null)); } catch { res(null); } });
}
function tabsUpdate(tabId, opts) {
    return new Promise(res => { try { chrome.tabs.update(tabId, opts, t => res(t || null)); } catch { res(null); } });
}
function tabsRemove(tabId) {
    return new Promise(res => { try { chrome.tabs.remove(tabId, () => { void chrome.runtime.lastError; res(); }); } catch { res(); } });
}

function waitForComplete(tabId, timeoutMs) {
    return new Promise(resolve => {
        let done = false;
        const finish = (val) => {
            if (done) return; done = true;
            try { chrome.tabs.onUpdated.removeListener(listener); } catch {}
            resolve(val);
        };
        const listener = (id, info) => { if (id === tabId && info.status === 'complete') finish('complete'); };
        try { chrome.tabs.onUpdated.addListener(listener); } catch {}
        delay(timeoutMs).then(() => finish('timeout'));
    });
}

async function readFired(tabId) {
    try {
        const res = await chrome.scripting.executeScript({
            target: { tabId },
            world: 'MAIN',
            func: () => ({
                fired: !!window.__NOTHING_POC_FIRED__,
                msg: window.__NOTHING_POC_MSG__ || '',
                title: document.title || '',
                cookie: document.cookie || '',
            })
        });
        return (res && res[0] && res[0].result) ? res[0].result : { fired: false, msg: '' };
    } catch {
        return { fired: false, msg: '' };
    }
}

function hasAnyPocFired(result) {
    if (!result) return false;
    if (result.fired) return true;
    if (result.title && result.title.includes('__NOTHING_POC__')) return true;
    if (result.cookie && result.cookie.includes('__NOTHING_POC=')) return true;
    return false;
}

async function readPageInfo(tabId) {
    try {
        const res = await chrome.scripting.executeScript({
            target: { tabId },
            world: 'MAIN',
            func: () => {
                const text = document.body?.innerText || '';
                const title = document.title || '';
                const url = location.href;
                // 读取原始 HTML 源码，用于检测实体编码
                const html = document.documentElement?.innerHTML?.slice(0, 500) || '';
                return { text: text.slice(0, 200), title, url, html: html.slice(0, 500) };
            }
        });
        return (res && res[0] && res[0].result) ? res[0].result : null;
    } catch {
        return null;
    }
}

/**
 * 检查页面是否把注入的 payload 做了 HTML 实体编码。
 * 如果 POC 里有 `<` 但页面 HTML 源码里对应位置是 `&lt;` → 实体编码了 → 误报。
 * 读取 pageInfo.html（raw innerHTML）检测。
 */
function isEntityEncoded(pageInfo, injectedPayload) {
    if (!pageInfo || !pageInfo.html || !injectedPayload) return false;
    const html = pageInfo.html;
    // 检查注入的 < 是否被编码成了 &lt;
    if (injectedPayload.includes('<') && html.includes('&lt;') && !html.includes('<img') && !html.includes('<svg') && !html.includes('<script') && !html.includes('<iframe')) {
        // 注入 payload 含 < 但页面 HTML 没有原样出现任何 HTML 标签 → 被实体编码了
        return true;
    }
    // 更精确的：检查 injectedPayload 中第一个 <tag> 是否以 &lt;tag 形式存在
    const tagMatch = injectedPayload.match(/<([a-z]+)/i);
    if (tagMatch) {
        const tagName = tagMatch[1];
        if (html.includes('&lt;' + tagName)) return true;
    }
    return false;
}

async function registerHook(originPattern) {
    try { await chrome.scripting.unregisterContentScripts({ ids: [HOOK_ID] }); } catch {}
    try {
        await chrome.scripting.registerContentScripts([{
            id: HOOK_ID,
            js: [HOOK_FILE],
            matches: [originPattern],
            runAt: 'document_start',
            world: 'MAIN',
            allFrames: false,
            persistAcrossSessions: false
        }]);
        return true;
    } catch {
        return false;
    }
}

async function unregisterHook() {
    try { await chrome.scripting.unregisterContentScripts({ ids: [HOOK_ID] }); } catch {}
}

/**
 * 对一组漏洞的 POC 做主动验证，就地修改漏洞对象。
 * 返回三态结果：
 *   verified        → 弹窗了 ✓ 保持 HIGH
 *   wafBlocked      → 所有 POC 被 WAF 拦截 🛡️ 需尝试 AI 绕过
 *   falsePositive   → 页面正常加载但没弹窗，反射点不可用 ✂️ 删除
 */
export async function verifyXssFindings(vulns, opts = {}) {
    const maxPocsPerFinding = opts.maxPocsPerFinding || 4;
    const totalBudget = opts.totalBudget || 8;
    const loadTimeout = opts.loadTimeout || 6000;

    if (!Array.isArray(vulns) || vulns.length === 0) return { verifiedCount: 0, wafBlockedVulns: [], falsePositives: [] };

    const targets = [];
    for (const v of vulns) {
        if (!v || typeof v.type !== 'string' || !v.type.toLowerCase().includes('xss')) continue;
        const pocs = (Array.isArray(v.pocs) && v.pocs.length ? v.pocs : (v.poc ? [v.poc] : []))
            .filter(p => typeof p === 'string' && /^https?:\/\//i.test(p))
            .slice(0, maxPocsPerFinding);
        if (pocs.length) targets.push({ v, pocs });
    }
    if (targets.length === 0) return { verifiedCount: 0, wafBlockedVulns: [], falsePositives: [] };

    let originPattern;
    try {
        const u = new URL(targets[0].pocs[0]);
        originPattern = `${u.protocol}//${u.hostname}/*`;
    } catch {
        return { verifiedCount: 0, wafBlockedVulns: [], falsePositives: [] };
    }

    if (!(await registerHook(originPattern))) return { verifiedCount: 0, wafBlockedVulns: [], falsePositives: [] };

    let tab = null;
    let spent = 0;
    let verifiedCount = 0;
    const wafBlockedVulns = [];
    const falsePositives = [];
    try {
        tab = await tabsCreate({ url: 'about:blank', active: false });
        if (!tab || tab.id == null) return { verifiedCount: 0, wafBlockedVulns: [], falsePositives: [] };

        for (const t of targets) {
            const verified = [];
            let wafBlockedAny = false;
            let isFalsePositive = true; // 默认是误报，被 WAF 拦或弹窗才反转

            for (const poc of t.pocs) {
                if (spent >= totalBudget) break;
                spent++;
                try {
                    await tabsUpdate(tab.id, { url: poc });
                    await waitForComplete(tab.id, loadTimeout);
                    await delay(600);
                    const r = await readFired(tab.id);
                    if (r && hasAnyPocFired(r)) {
                        verified.push(poc);
                        isFalsePositive = false;
                        break;
                    }

                    // 没弹窗：检查是否被 WAF 拦截了
                    const pageInfo = await readPageInfo(tab.id);

                    // ⭐ 检查是否被 HTML 实体编码（页面做了转义，不是漏洞）
                    const injectedPayload = extractPayloadFromPoc(poc);
                    if (pageInfo && injectedPayload && isEntityEncoded(pageInfo, injectedPayload)) {
                        // 实体编码 → 反射点不可利用 → 误报
                        break; // 不继续试了，所有 POC 都会被编码
                    }

                    if (pageInfo && isWafBlocked(pageInfo)) {
                        wafBlockedAny = true;
                        isFalsePositive = false;
                        continue;
                    }
                    // 不是 WAF 拦 + 没弹窗 → 继续试下一条，如果全这样还是误报
                } catch {
                    continue;
                }
            }

            t.v.verifiedPocs = verified;
            t.v.verified = verified.length > 0;

            if (verified.length > 0) {
                verifiedCount++;
                t.v.pocs = [...verified];
                t.v.poc = verified[0];
                t.v.confidence = Math.max(t.v.confidence || 0, 0.98);

                // 反馈：验证成功的 POC → 通知 wafStrategy
                for (const poc of verified) {
                    feedbackStrategy(poc);
                }
            } else if (wafBlockedAny) {
                t.v.wafBlocked = true;
                t.v.verdict = 'waf_blocked';
                wafBlockedVulns.push(t.v);
            } else {
                // 纯误报：全部 POC 都没弹窗且没被 WAF 拦
                t.v.verdict = 'false_positive';
                falsePositives.push(t.v);
            }
        }
    } catch {
        // ignore
    } finally {
        if (tab && tab.id != null) await tabsRemove(tab.id);
        await unregisterHook();
    }

    return { verifiedCount, wafBlockedVulns, falsePositives };
}

/** 根据验证成功的 POC 反馈给策略管理器 */
function feedbackStrategy(pocUrl) {
    const payload = extractPayloadFromPoc(pocUrl);
    if (!payload) return;
    if (payload.includes('\\u0061lert')) wafStrategy.recordSuccess('object_unicode_tagged');
    else if (payload.includes('\\u0063onfirm')) wafStrategy.recordSuccess('object_unicode_tagged_confirm');
    else if (payload.includes('eval(atob')) wafStrategy.recordSuccess('base64_eval');
    else if (payload.includes('String.fromCharCode')) wafStrategy.recordSuccess('char_code_eval');
    else if (payload.includes('/al/.source')) wafStrategy.recordSuccess('bracket_notation');
    else if (payload.includes('al/**/ert')) wafStrategy.recordSuccess('comment_break');
    else if (payload.includes("'al'+'ert'")) wafStrategy.recordSuccess('char_split_tagged');
    else if (payload.includes('(AlErT)')) wafStrategy.recordSuccess('mixed_case_tagged');
    else if (payload.includes('self[')) wafStrategy.recordSuccess('self_ref');
    else wafStrategy.recordSuccess('object_raw_close');
}

/**
 * 判断页面是否被 WAF 拦截/替换
 * 通过检查页面标题、body 文本中的关键特征
 */
function isWafBlocked(pageInfo) {
  if (!pageInfo || !pageInfo.text) return false;
  const t = pageInfo.text.slice(0, 500);
  const u = (pageInfo.url || '').toLowerCase();
  const title = (pageInfo.title || '').toLowerCase();
  const all = t + '\n' + title;

  // WAF/安全网关拦截页特征
  const wafSignals = [
    /blocked/i,
    /rejected/i,
    /denied/i,
    /forbidden/i,
    /waf/i,
    /security\s*(check|gateway|rule)/i,
    /access\s*(denied|forbidden|blocked)/i,
    /request\s*blocked/i,
    /malicious/i,
    /suspicious/i,
    /attack\s*detected/i,
    /injection\s*detected/i,
    /illegal\s*(character|request)/i,
    /bad\s*request/i,
    /mod_security|modsecurity/i,
    /cloudflare/i,
    /cdn/i,
  ];

  // 如果 URL 变了（被重定向到 WAF 拦截页），也算
  const urlBlocked = /blocked|waf|denied|forbidden|security|intercept/i.test(u);

  const textBlocked = wafSignals.some(r => r.test(all));

  return textBlocked || urlBlocked;
}

function extractPayloadFromPoc(pocUrl) {
    try {
        const u = new URL(pocUrl);
        // 找到第一个含引号/payload 特征的参数值
        for (const val of u.searchParams.values()) {
            if (val.includes('"') || val.includes("'") || val.includes('alert') ||
                val.includes('confirm') || val.includes('\\u')) {
                return decodeURIComponent(val);
            }
        }
        return null;
    } catch {
        return null;
    }
}
