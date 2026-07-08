/**
 * 主动 POC 验证
 * 在后台标签逐条加载候选 POC，配合 document_start 注入的 MAIN world alert hook，
 * 检测 payload 是否真的执行（alert/confirm/prompt 被调用）。只有实测弹窗的 POC 才标记为已验证。
 *
 * 设计要点：
 * - 反射型 XSS 在页面解析时同步执行，必须在 document_start 就 hook 住 alert，因此用
 *   chrome.scripting.registerContentScripts 注册 MAIN world 内容脚本（public/poc-hook.js）。
 * - hook 只把弹窗记录成 window 标志、不真正弹出，避免后台标签被模态框卡住。
 * - 验证仅作用于目标 host，用完立即注销，避免遗留全局注入。
 */

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

// 等待标签加载完成或超时
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

// 读取 MAIN world 里 hook 设置的弹窗标志
async function readFired(tabId) {
    try {
        const res = await chrome.scripting.executeScript({
            target: { tabId },
            world: 'MAIN',
            func: () => ({ fired: !!window.__NOTHING_POC_FIRED__, msg: window.__NOTHING_POC_MSG__ || '' })
        });
        return (res && res[0] && res[0].result) ? res[0].result : { fired: false, msg: '' };
    } catch {
        return { fired: false, msg: '' };
    }
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
 * 对一组漏洞的 POC 做主动验证，就地给漏洞对象打上：
 *   v.verifiedPocs（实测弹窗的 POC 列表）、v.verified（是否有可用 POC）
 * 并把已验证 POC 提到 v.pocs 最前、设为 v.poc 主推。
 *
 * @returns {number} 验证通过的漏洞数
 */
export async function verifyXssFindings(vulns, opts = {}) {
    const maxPocsPerFinding = opts.maxPocsPerFinding || 3;
    const totalBudget = opts.totalBudget || 8;   // 单次扫描最多加载多少个 POC 页面
    const loadTimeout = opts.loadTimeout || 6000;

    if (!Array.isArray(vulns) || vulns.length === 0) return 0;

    // 收集待验证：只测反射型 XSS 且是 http(s) GET URL 的 POC
    const targets = [];
    for (const v of vulns) {
        if (!v || typeof v.type !== 'string' || !v.type.toLowerCase().includes('xss')) continue;
        const pocs = (Array.isArray(v.pocs) && v.pocs.length ? v.pocs : (v.poc ? [v.poc] : []))
            .filter(p => typeof p === 'string' && /^https?:\/\//i.test(p))
            .slice(0, maxPocsPerFinding);
        if (pocs.length) targets.push({ v, pocs });
    }
    if (targets.length === 0) return 0;

    let originPattern;
    try {
        const u = new URL(targets[0].pocs[0]);
        originPattern = `${u.protocol}//${u.hostname}/*`;
    } catch {
        return 0;
    }

    if (!(await registerHook(originPattern))) return 0;

    let tab = null;
    let spent = 0;
    let verifiedCount = 0;
    try {
        tab = await tabsCreate({ url: 'about:blank', active: false });
        if (!tab || tab.id == null) return 0;

        for (const t of targets) {
            const verified = [];
            for (const poc of t.pocs) {
                if (spent >= totalBudget) break;
                spent++;
                try {
                    await tabsUpdate(tab.id, { url: poc });
                    await waitForComplete(tab.id, loadTimeout);
                    await delay(600); // 给"加载后立即触发"的弹窗留点时间
                    const r = await readFired(tab.id);
                    if (r.fired) { verified.push(poc); break; } // 该漏洞已找到可用 POC，够了
                } catch {}
            }

            t.v.verifiedPocs = verified;
            t.v.verified = verified.length > 0;
            if (verified.length > 0) {
                verifiedCount++;
                // 质量优先：既然实测出能打的，就只留验证通过的，丢掉打不动/被拦的候选（它们纯属噪音）
                t.v.pocs = [...verified];
                t.v.poc = verified[0];
                // 置信度提升到实测级别
                t.v.confidence = Math.max(t.v.confidence || 0, 0.98);
            }
            // verified.length === 0 时保留原候选，供人工手动尝试
        }
    } catch {
        // ignore，保底不影响主流程
    } finally {
        if (tab && tab.id != null) await tabsRemove(tab.id);
        await unregisterHook();
    }

    return verifiedCount;
}
