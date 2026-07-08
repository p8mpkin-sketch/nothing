const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Private / reserved IPv4 range check.
export function isPrivateIP(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    const p = ip.split('.').map(Number);
    return p[0] === 10
        || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
        || (p[0] === 192 && p[1] === 168)
        || p[0] === 127            // loopback
        || p[0] === 0              // this network
        || (p[0] === 169 && p[1] === 254) // link-local
        || (p[0] === 100 && p[1] >= 64 && p[1] <= 127); // CGNAT
}

// Whether a hostname is an internal / intranet target that has no public ICP or
// geo info (private IP, loopback, single-label host, or internal-use TLD).
export function isInternalHost(hostname) {
    if (!hostname) return true;
    const h = hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
    if (h === 'localhost') return true;
    if (isPrivateIP(h)) return true;
    // IPv6 loopback / unique-local (fc00::/7) / link-local (fe80::/10)
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return true;
    // internal-use / non-routable TLDs
    if (/\.(local|localhost|internal|intranet|intra|lan|corp|home|test|example|invalid|localdomain)$/.test(h)) return true;
    // single-label hostname (no dot) e.g. "gitlab", "jenkins"
    if (!h.includes('.')) return true;
    return false;
}

// ICP is registered on the registrable (root) domain, not on subdomains.
// e.g. basic.ln.smartedu.cn -> smartedu.cn.  Handles multi-level cn/other suffixes.
export function getRootDomain(hostname) {
    const multiSuffix = ['com.cn', 'edu.cn', 'gov.cn', 'org.cn', 'net.cn', 'ac.cn',
        'co.jp', 'co.uk', 'co.kr', 'com.hk'];
    const parts = String(hostname || '').split('.');
    if (parts.length <= 2) return hostname;
    for (const suf of multiSuffix) {
        if (hostname.endsWith('.' + suf)) {
            return parts.slice(-(suf.split('.').length + 1)).join('.');
        }
    }
    return parts.slice(-2).join('.');
}

async function getCached(key) {
    try {
        const data = await chrome.storage.session.get(key);
        const entry = data[key];
        if (entry && Date.now() - entry.ts < CACHE_TTL) return entry.data;
    } catch (e) {}
    return null;
}

async function setCache(key, data) {
    try {
        await chrome.storage.session.set({ [key]: { data, ts: Date.now() } });
    } catch (e) {}
}

/**
 * Query ICP registration info
 * @param {string} domain
 */
// ── ICP resolver ────────────────────────────────────────────────────────────
// A source-agnostic resolver: each provider is an adapter that queries an
// independent endpoint and normalizes the result to a common shape
// { code:200, icp, unit, type, time, domain, source }. Providers are tried in
// order; the first hit wins. All ICP data ultimately originates from 工信部
// (MIIT) — these are just independent proxies. Adding/removing a source, or
// plugging in your own API key, is a one-place change here.

function normalizeApihz(j, domain) {
    if (j && j.code === 200 && j.icp) {
        return { code: 200, icp: j.icp, unit: j.unit || '', type: j.type || '', time: j.time || '', domain, source: 'apihz' };
    }
    return null;
}

// Built-in providers (public/best-effort). User-provided credentials, if set in
// settings (icpApiId / icpApiKey), are prepended so your own quota is used first.
const ICP_PROVIDERS = [
    {
        name: 'apihz',
        async query(domain) {
            const res = await fetch(
                `https://cn.apihz.cn/api/wangzhan/icp.php?id=10006978&key=c7e331a036de5934b6687b7a43fa5d99&domain=${encodeURIComponent(domain)}`,
                { signal: AbortSignal.timeout(8000) }
            );
            return normalizeApihz(await res.json(), domain);
        }
    },
    {
        name: 'vvhan',
        async query(domain) {
            const res = await fetch(
                `https://api.vvhan.com/api/icp?url=${encodeURIComponent(domain)}`,
                { signal: AbortSignal.timeout(8000) }
            );
            const j = await res.json();
            const info = j?.info || j?.data;
            const icp = info?.icp || info?.icpCode;
            if (j?.success && icp) {
                return { code: 200, icp, unit: info.name || info.unit || '', type: info.nature || info.type || '', domain, source: 'vvhan' };
            }
            return null;
        }
    },
];

async function buildIcpProviders() {
    const providers = [...ICP_PROVIDERS];
    try {
        const { settings } = await chrome.storage.local.get('settings');
        const id = settings?.icpApiId, key = settings?.icpApiKey;
        if (id && key) {
            // Your own apihz credentials — tried first (uses your quota, not shared).
            providers.unshift({
                name: 'apihz-user',
                async query(domain) {
                    const res = await fetch(
                        `https://cn.apihz.cn/api/wangzhan/icp.php?id=${encodeURIComponent(id)}&key=${encodeURIComponent(key)}&domain=${encodeURIComponent(domain)}`,
                        { signal: AbortSignal.timeout(8000) }
                    );
                    return normalizeApihz(await res.json(), domain);
                }
            });
        }
    } catch (e) {}
    return providers;
}

export async function queryICP(domain) {
    // IP addresses never have an ICP record (check before root-domain reduction,
    // which would otherwise mangle an IP like 10.0.0.1 into "0.1").
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        return { code: 0, error: 'IP 地址无备案', domain };
    }

    // Query the root domain — ICP filings are on the registrable domain, not subdomains.
    const rootDomain = getRootDomain(domain);

    const cacheKey = `icp_${rootDomain}`;
    const cached = await getCached(cacheKey);
    if (cached) return cached;

    const providers = await buildIcpProviders();
    let lastError = null;
    for (const provider of providers) {
        try {
            const result = await provider.query(rootDomain);
            if (result) {
                await setCache(cacheKey, result);
                return result;
            }
        } catch (e) {
            lastError = e;
            // fall through to next provider
        }
    }

    // No provider returned a hit — treat as "not filed / lookup failed" (not cached,
    // so a later visit can retry once a source recovers).
    return { code: 404, error: lastError?.message || '未查询到备案信息', domain: rootDomain };
}

/**
 * Query domain weight / SEO info
 * @param {string} domain
 */
export async function queryDomainWeight(domain) {
    const cacheKey = `weight_${domain}`;
    const cached = await getCached(cacheKey);
    if (cached) return cached;

    try {
        const res = await fetch(
            `https://api.mir6.com/api/bdqz?myKey=84fbd322b048f19626e861932ec7d572&domain=${encodeURIComponent(domain)}&type=json`,
            { signal: AbortSignal.timeout(8000) }
        );
        const json = await res.json();
        await setCache(cacheKey, json);
        return json;
    } catch (e) {
        return { error: e.message };
    }
}

/**
 * Query IP geolocation info
 * @param {string} ip
 */
export async function queryIPInfo(ip) {
    const cacheKey = `ip_${ip}`;
    const cached = await getCached(cacheKey);
    if (cached) return cached;

    try {
        const res = await fetch(
            `https://api.mir6.com/api/ip_json?myKey=7f5860bc55587662c37cf678a7871ad0&ip=${encodeURIComponent(ip)}`,
            { signal: AbortSignal.timeout(8000) }
        );
        const json = await res.json();
        await setCache(cacheKey, json);
        return json;
    } catch (e) {
        return { error: e.message };
    }
}

/**
 * Resolve hostname to IP via DNS-over-HTTPS
 * @param {string} hostname
 */
export async function resolveIP(hostname) {
    const cacheKey = `dns_${hostname}`;
    const cached = await getCached(cacheKey);
    if (cached) return cached;

    try {
        const res = await fetch(
            `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
            { signal: AbortSignal.timeout(5000) }
        );
        const json = await res.json();
        const ip = json.Answer?.[0]?.data || null;
        await setCache(cacheKey, ip);
        return ip;
    } catch (e) {
        return null;
    }
}
