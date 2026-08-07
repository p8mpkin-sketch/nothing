import { addLog } from './logger';
import { ruleEngine } from './ruleEngine';
import { getParentHierarchies } from './urlParser';
import { isExcluded } from '../utils/exclusionMatcher';
import { pendingProbes } from './probeRegistry';
import { matchContent } from './matchHelper';

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

        // Cache for loadSettings() — avoid chrome.storage read on every scan() call
        this._settingsLoadedAt = 0;
        this._settingsCacheTTL = 5000; // 5s TTL between full reloads

        this.loadSettings();
    }

    // Inject custom request headers (incl. forbidden ones like Cookie) for a probe
    // via declarativeNetRequest, since fetch() silently drops forbidden headers.
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
                    condition: { urlFilter: targetUrl, resourceTypes: ['xmlhttprequest', 'other'] }
                }]
            });
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
        delete this.tabHosts[tabId];
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
            const [ruleId, url] = key.split('|', 2);
            if (url) {
                try {
                    const hostname = new URL(url).hostname;
                    const hostSet = this.globalScannedPaths.get(hostname);
                    if (hostSet) hostSet.delete(key);
                } catch {}
            }
        }
    }

    // Helper to expand probe paths with simple regex alternation support
    expandProbePath(pathStr) {
        if (!pathStr) return [];
        let cleanStr = pathStr.trim();
        if (cleanStr.startsWith('(') && cleanStr.endsWith(')')) {
            cleanStr = cleanStr.slice(1, -1);
        }
        if (cleanStr.includes('|')) {
            return cleanStr.split('|').map(p => p.trim()).filter(p => p.length > 0);
        }
        return [cleanStr];
    }

    async loadSettings() {
        // TTL-based cache: avoid chrome.storage.local.get() on every HTTP request.
        // chrome.storage.onChanged already refreshes rules proactively (see bottom of file).
        const now = Date.now();
        if (this._settingsLoadedAt && now - this._settingsLoadedAt < this._settingsCacheTTL) return;

        const data = await chrome.storage.local.get(['settings', 'rules', 'exclusions']);
        this.enabled = data.settings?.activeScan !== false;

        const allRules = data.rules || [];
        this.activeRules = allRules.filter(r => r.probePath && r.enabled);
        this.exclusions = data.exclusions || [];
        this._settingsLoadedAt = now;

        console.log('[Scanner] enabled:', this.enabled, '| activeRules:', this.activeRules.map(r => `${r.name}(${r.probePath})`));
    }

    /**
     * Scan a target URL by probing configured paths.
     */
    async scan(currentUrl, tabId) {
        // Quick gate without storage read
        if (!this.enabled || this.activeRules.length === 0) return;

        await this.loadSettings();

        // Re-check after loadSettings (might have been disabled)
        if (!this.enabled || this.activeRules.length === 0) return;

        if (isExcluded(currentUrl, this.exclusions)) return;

        try {
            const urlObj = new URL(currentUrl);
            const currentHost = urlObj.hostname;
            this.tabHosts[tabId] = currentHost;

            if (!this.globalScannedPaths.has(currentHost)) {
                this.globalScannedPaths.set(currentHost, new Set());
            }
            const hostScannedPaths = this.globalScannedPaths.get(currentHost);

            const basePaths = getParentHierarchies(currentUrl);

            for (const rule of this.activeRules) {
                // Per-host dedup for whole-site fingerprints
                if (ruleEngine.isHostDedupeRule(rule) && ruleEngine.hasHostMatch(rule.id, currentUrl)) {
                    continue;
                }

                const matchedParentPaths = new Set();

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

                const probePaths = this.expandProbePath(rule.probePath);
                for (const rawProbePath of probePaths) {
                    const probePath = rawProbePath.startsWith('/') ? rawProbePath.substring(1) : rawProbePath;

                    for (const basePath of basePaths) {
                        const base = basePath.endsWith('/') ? basePath : basePath + '/';
                        const targetUrl = base + probePath;

                        if (ruleEngine.isMatched(rule.id, targetUrl)) continue;

                        let shouldSkipDueToParent = false;
                        for (const matchedPath of matchedParentPaths) {
                            if (basePath !== matchedPath && basePath.startsWith(matchedPath)) {
                                shouldSkipDueToParent = true;
                                break;
                            }
                        }
                        if (shouldSkipDueToParent) continue;

                        const uniqueKey = `${rule.id}|${targetUrl}`;
                        if (hostScannedPaths.has(uniqueKey)) {
                            const ts = this.scannedPathTimestamps.get(uniqueKey);
                            if (ts && Date.now() - ts <= this.scanTTL) continue;
                            hostScannedPaths.delete(uniqueKey);
                            this.scannedPathTimestamps.delete(uniqueKey);
                        }

                        hostScannedPaths.add(uniqueKey);
                        this.scannedPathTimestamps.set(uniqueKey, Date.now());

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

        const dnrId = await this.applyHeaderInjection(targetUrl, rule.requestHeaders);

        try {
            const fetchOptions = { credentials: 'include', redirect: 'manual' };

            if (rule.matchScope === 'response_header') {
                pendingProbes.set(targetUrl, { rule, tabId });
                setTimeout(() => pendingProbes.delete(targetUrl), 20000);
            }

            const response = await fetch(targetUrl, fetchOptions);

            if (rule.matchScope === 'response_header') {
                const headerList = [];
                for (const [k, v] of response.headers.entries()) {
                    headerList.push(`${k}: ${v}`);
                }
                const headerString = headerList.join('\n');
                const { isMatch } = matchContent(rule, headerString, response.status);
                if (isMatch) {
                    ruleEngine.handleMatch(rule, { tabId, url: targetUrl, type: 'active-probe-header', statusCode: response.status });
                    addLog(rule.name, targetUrl, 'match', 'Pattern found in Response Headers');
                }
                return;
            }

            // Body match
            const body = await response.text();
            const { isMatch } = matchContent(rule, body, response.status);
            if (isMatch) {
                ruleEngine.handleMatch(rule, { tabId, url: targetUrl, type: 'active-probe-body', statusCode: response.status });
                addLog(rule.name, targetUrl, 'match', 'Pattern found in Body');
            }

        } catch (e) {
            // Transient errors (network/timeout): don't mark as scanned, allow retry
            pendingProbes.delete(targetUrl);
            const uniqueKey = `${rule.id}|${targetUrl}`;
            try {
                const hostname = new URL(targetUrl).hostname;
                const hostSet = this.globalScannedPaths.get(hostname);
                if (hostSet) hostSet.delete(uniqueKey);
                this.scannedPathTimestamps.delete(uniqueKey);
            } catch {}
            console.warn(`[Scanner] Probe failed for ${targetUrl}:`, e.message);
        } finally {
            await this.removeHeaderInjection(dnrId);
        }
    }
}

export const activeScanner = new ActiveScanner();

// Reactive refresh: when settings/rules/exclusions change, reload immediately.
// The 5s cache TTL in loadSettings() acts as a backstop.
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.settings || changes.rules || changes.exclusions) {
            activeScanner._settingsLoadedAt = 0;
            activeScanner.loadSettings();
        }
    }
});
