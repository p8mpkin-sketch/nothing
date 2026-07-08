import { addLog } from './logger';
import { getParentHierarchies } from './urlParser';
import { isExcluded } from '../utils/exclusionMatcher';
import { pendingProbes } from './probeRegistry';

/**
 * Active Scanner to probe specific paths on the target domain.
 */
export class ActiveScanner {
    constructor() {
        this.enabled = false;
        this.activeRules = [];
        this.exclusions = [];
        this.globalScannedPaths = new Map(); // hostname -> Set<string> (persistent across page refreshes with TTL)
        this.scannedPathTimestamps = new Map(); // uniqueKey -> timestamp (for TTL cleanup)
        this.tabHosts = {}; // tabId -> hostname
        this.scanTTL = 30 * 60 * 1000; // 30 minutes TTL for scanned paths
        this.dnrCounter = 0; // for unique declarativeNetRequest session rule ids
        this.loadSettings();
    }

    // Inject custom request headers (incl. forbidden ones like Cookie) for a probe
    // via declarativeNetRequest, since fetch() silently drops forbidden headers.
    // Returns the session rule id (to remove afterwards), or null if nothing to do.
    async applyHeaderInjection(targetUrl, requestHeaders) {
        if (!requestHeaders || !chrome.declarativeNetRequest?.updateSessionRules) return null;
        const headers = [];
        for (const line of requestHeaders.split('\n')) {
            const idx = line.indexOf(':');
            if (idx > 0) {
                const name = line.slice(0, idx).trim();
                const value = line.slice(idx + 1).trim();
                if (name && value) headers.push({ header: name, operation: 'set', value });
            }
        }
        if (headers.length === 0) return null;

        this.dnrCounter = (this.dnrCounter + 1) % 100000;
        const id = 100000 + this.dnrCounter;
        try {
            await chrome.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [id],
                addRules: [{
                    id,
                    priority: 1,
                    action: { type: 'modifyHeaders', requestHeaders: headers },
                    // Only match extension-initiated probe traffic (xhr/other), not the
                    // user's real page navigation, to avoid tampering with their session.
                    condition: { urlFilter: targetUrl, resourceTypes: ['xmlhttprequest', 'other'] }
                }]
            });
            console.log(`[Scanner] DNR header injection on for ${targetUrl}:`, headers.map(h => h.header).join(', '));
            return id;
        } catch (e) {
            console.warn('[Scanner] DNR header injection failed:', e?.message);
            return null;
        }
    }

    async removeHeaderInjection(id) {
        if (id == null || !chrome.declarativeNetRequest?.updateSessionRules) return;
        try {
            await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id] });
        } catch {}
    }

    reset(tabId, hostname) {
        // No longer clear globalScannedPaths on navigation
        // Instead, rely on TTL-based cleanup to prevent noise
        delete this.tabHosts[tabId];
        console.log(`[Scanner] Reset tab ${tabId} tracking (hostname: ${hostname})`);
    }

    // Clean up expired scanned paths based on TTL
    cleanupExpiredPaths() {
        const now = Date.now();
        const expiredKeys = [];

        for (const [key, ts] of this.scannedPathTimestamps.entries()) {
            if (now - ts > this.scanTTL) {
                expiredKeys.push(key);
            }
        }

        for (const key of expiredKeys) {
            this.scannedPathTimestamps.delete(key);
            // Remove from globalScannedPaths
            const [ruleId, url] = key.split('|', 2);
            if (url) {
                try {
                    const hostname = new URL(url).hostname;
                    const hostSet = this.globalScannedPaths.get(hostname);
                    if (hostSet) {
                        hostSet.delete(key);
                    }
                } catch {}
            }
        }

        if (expiredKeys.length > 0) {
            console.log(`[Scanner] Cleaned up ${expiredKeys.length} expired scan records`);
        }
    }

    // Helper to expand probe paths with simple regex alternation support
    // e.g. "(/actuator/|/actuator/env)" -> ["/actuator/", "/actuator/env"]
    expandProbePath(pathStr) {
        if (!pathStr) return [];

        let cleanStr = pathStr.trim();

        // Remove outer parentheses if present
        if (cleanStr.startsWith('(') && cleanStr.endsWith(')')) {
            cleanStr = cleanStr.slice(1, -1);
        }

        // Split by pipe |
        if (cleanStr.includes('|')) {
            const paths = cleanStr.split('|').map(p => p.trim()).filter(p => p.length > 0);
            // console.log(`[Scanner] Expanded path '${pathStr}' to:`, paths);
            return paths;
        }

        return [cleanStr];
    }

    async loadSettings() {
        const data = await chrome.storage.local.get(['settings', 'rules', 'exclusions']);
        this.enabled = data.settings?.activeScan || false;

        const allRules = data.rules || [];
        this.activeRules = allRules.filter(r => r.probePath && r.enabled);
        this.exclusions = data.exclusions || [];

        console.log('[Scanner] enabled:', this.enabled, '| activeRules:', this.activeRules.map(r => `${r.name}(${r.probePath})`));
    }

    /**
     * Scan a target URL by probing configured paths.
     * @param {string} currentUrl
     * @param {number} tabId
     */
    async scan(currentUrl, tabId) {
        await this.loadSettings();

        if (!this.enabled || this.activeRules.length === 0) {
            return;
        }

        // Check exclusions
        if (isExcluded(currentUrl, this.exclusions)) {
            console.log(`[Scanner] Skipped excluded URL: ${currentUrl}`);
            return;
        }

        try {
            const urlObj = new URL(currentUrl);
            const currentHost = urlObj.hostname;

            // Track current host for this tab
            this.tabHosts[tabId] = currentHost;

            // Initialize global scan history for this hostname if not exists
            if (!this.globalScannedPaths.has(currentHost)) {
                this.globalScannedPaths.set(currentHost, new Set());
            }
            const hostScannedPaths = this.globalScannedPaths.get(currentHost);

            // Get all parent hierarchies (static paths already filtered by urlParser)
            const basePaths = getParentHierarchies(currentUrl);

            for (const rule of this.activeRules) {
                const { ruleEngine } = await import('./ruleEngine');

                // For whole-site framework fingerprints only: skip probing entirely
                // once the rule matched anywhere on this host — avoids duplicate hits
                // across dirs. Path-specific rules are unaffected (nginx sub-path apps).
                if (ruleEngine.isHostDedupeRule(rule) && ruleEngine.hasHostMatch(rule.id, currentUrl)) {
                    continue;
                }

                // Smart framework detection: only skip subdirectories if parent path already matched
                // This handles nginx reverse proxy scenarios where different paths map to different apps
                const matchedParentPaths = new Set();

                // Check which basePaths have already produced a matched targetUrl for this rule
                const probePaths0 = this.expandProbePath(rule.probePath);
                for (const basePath of basePaths) {
                    const base0 = basePath.endsWith('/') ? basePath : basePath + '/';
                    for (const rpp of probePaths0) {
                        const pp = rpp.startsWith('/') ? rpp.substring(1) : rpp;
                        if (ruleEngine.isMatched(rule.id, base0 + pp)) {
                            matchedParentPaths.add(basePath);
                            break;
                        }
                    }
                }

                // Expand probe path (support regex alternation)
                const probePaths = this.expandProbePath(rule.probePath);

                for (const rawProbePath of probePaths) {
                    const probePath = rawProbePath.startsWith('/') ? rawProbePath.substring(1) : rawProbePath;

                    for (const basePath of basePaths) {
                        // Ensure basePath ends with /
                        const base = basePath.endsWith('/') ? basePath : basePath + '/';
                        const targetUrl = base + probePath;

                        // Skip if this exact URL already matched
                        if (ruleEngine.isMatched(rule.id, targetUrl)) {
                            console.log(`[Scanner] Skipping already matched: ${targetUrl} for rule ${rule.name}`);
                            continue;
                        }

                        // Smart skip: only skip if a DIRECT parent path (not ancestor) already matched
                        // Example: if /api/ matched, skip /api/v1/, /api/v2/, but NOT /admin/
                        let shouldSkipDueToParent = false;
                        for (const matchedPath of matchedParentPaths) {
                            // Check if current basePath is a direct child of matchedPath
                            if (basePath !== matchedPath && basePath.startsWith(matchedPath)) {
                                shouldSkipDueToParent = true;
                                console.log(`[Scanner] Skipping ${targetUrl} - parent path ${matchedPath} already matched for rule ${rule.name}`);
                                break;
                            }
                        }
                        if (shouldSkipDueToParent) continue;

                        const uniqueKey = `${rule.id}|${targetUrl}`;

                        // Check global scan history for this hostname (persistent across refreshes with TTL)
                        if (hostScannedPaths.has(uniqueKey)) {
                            // Check if expired
                            const ts = this.scannedPathTimestamps.get(uniqueKey);
                            if (ts && Date.now() - ts <= this.scanTTL) {
                                // console.log(`[Scanner] Skipping already scanned (no match): ${uniqueKey}`);
                                continue;
                            } else {
                                // Expired, remove and re-scan
                                hostScannedPaths.delete(uniqueKey);
                                this.scannedPathTimestamps.delete(uniqueKey);
                            }
                        }

                        // Mark as scanned in global history with timestamp
                        hostScannedPaths.add(uniqueKey);
                        this.scannedPathTimestamps.set(uniqueKey, Date.now());

                        // Periodic cleanup (every 100 scans)
                        if (this.scannedPathTimestamps.size % 100 === 0) {
                            this.cleanupExpiredPaths();
                        }

                        await this.probeTarget(targetUrl, rule, tabId);
                    }
                }
            }
        } catch (e) {
            console.error('[Scanner] Error:', e);
        }
    }

    async probeTarget(targetUrl, rule, tabId) {
        console.log(`[Scanner] Probing: ${targetUrl}`);

        // Inject custom request headers (Cookie etc.) via declarativeNetRequest,
        // because fetch() cannot set forbidden headers like Cookie.
        const dnrId = await this.applyHeaderInjection(targetUrl, rule.requestHeaders);

        try {
            const fetchOptions = {
                credentials: 'include',
                redirect: 'manual'
            };

            // Register the probe so networkMonitor.onHeadersReceived (which uses
            // 'extraHeaders' and CAN read Set-Cookie) matches its response headers.
            // fetch()'s response.headers cannot read Set-Cookie, so this is required
            // for cookie-based fingerprints (e.g. shiro rememberMe=deleteMe).
            if (rule.matchScope === 'response_header') {
                pendingProbes.set(targetUrl, { rule, tabId });
                // Safety cleanup in case webRequest never fires for this request.
                setTimeout(() => pendingProbes.delete(targetUrl), 20000);
            }

            const response = await fetch(targetUrl, fetchOptions);
            console.log(`[Scanner] Response from ${targetUrl}: ${response.status}`);

            const { ruleEngine } = await import('./ruleEngine');

            if (rule.matchScope === 'response_header') {
                // Primary matching (incl. Set-Cookie) happens in onHeadersReceived.
                // Here we ALSO match the headers fetch() can see, as a fallback for
                // environments where webRequest doesn't observe the SW fetch.
                const headerList = [];
                for (const [k, v] of response.headers.entries()) {
                    headerList.push(`${k}: ${v}`);
                }
                const headerString = headerList.join('\n');
                console.log(`[Scanner] fetch-visible headers for ${targetUrl}:`, headerString || '(none)');

                if (this.matchContent(rule, headerString, response.status)) {
                    ruleEngine.handleMatch(rule, { tabId, url: targetUrl, type: 'active-probe-header', statusCode: response.status });
                    addLog(rule.name, targetUrl, 'match', 'Pattern found in Response Headers');
                }
                return;
            }

            // Body match
            const contentToCheck = await response.text();
            if (this.matchContent(rule, contentToCheck, response.status)) {
                ruleEngine.handleMatch(rule, { tabId, url: targetUrl, type: 'active-probe-body', statusCode: response.status });
                addLog(rule.name, targetUrl, 'match', 'Pattern found in Body');
            }

        } catch (e) {
            pendingProbes.delete(targetUrl);
            console.warn(`[Scanner] Probe failed for ${targetUrl}:`, e.message);
        } finally {
            await this.removeHeaderInjection(dnrId);
        }
    }

    // Shared status + content matching used by body/header probe paths.
    matchContent(rule, content, statusCode) {
        const statusMatch = rule.matchStatusCode
            ? rule.matchStatusCode.split(',').map(c => c.trim()).includes(String(statusCode))
            : true;
        let contentMatch = false;
        if (rule.pattern === '^$') {
            contentMatch = !content || content.length === 0;
        } else if (rule.matchType === 'regex') {
            try { contentMatch = new RegExp(rule.pattern, 'i').test(content); } catch {}
        } else {
            contentMatch = (content || '').toLowerCase().replace(/\s+/g, ' ')
                .includes(rule.pattern.toLowerCase().replace(/\s+/g, ' '));
        }
        return rule.matchStatusCode
            ? (rule.matchCondition === 'or' ? (statusMatch || contentMatch) : (statusMatch && contentMatch))
            : contentMatch;
    }
}

export const activeScanner = new ActiveScanner();

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.settings || changes.rules || changes.exclusions) {
            activeScanner.loadSettings();
        }
    }
});
