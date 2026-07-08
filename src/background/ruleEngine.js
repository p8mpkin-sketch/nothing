import { addLog } from './logger';
import { isExcluded } from '../utils/exclusionMatcher';

/**
 * Rule Engine for matching content against user-defined rules.
 */

// Match cache with TTL to prevent duplicate alerts on page refresh.
// Backed by chrome.storage.session so it SURVIVES service-worker restarts (MV3
// kills the SW after ~30s idle; without persistence the cache was lost and every
// refresh re-alerted). Session storage clears on browser close, so a fresh browser
// session gets fresh alerts. In-memory Map is the source of truth for sync reads;
// writes are mirrored to storage.session (debounced).
class MatchCache {
    constructor(ttlMs = 30 * 60 * 1000, persistKey = null) { // 30 minutes default
        this.cache = new Map(); // key -> { ts: timestamp }
        this.ttlMs = ttlMs;
        this.persistKey = persistKey;
        this._saveTimer = null;
        if (persistKey) this._load();
    }

    async _load() {
        try {
            const data = await chrome.storage.session.get(this.persistKey);
            const arr = data[this.persistKey];
            if (Array.isArray(arr)) {
                const now = Date.now();
                for (const [k, ts] of arr) {
                    if (now - ts <= this.ttlMs) this.cache.set(k, { ts });
                }
            }
        } catch (e) {}
    }

    _scheduleSave() {
        if (!this.persistKey || this._saveTimer) return;
        this._saveTimer = setTimeout(() => {
            this._saveTimer = null;
            const arr = [...this.cache.entries()].map(([k, v]) => [k, v.ts]);
            try { chrome.storage.session.set({ [this.persistKey]: arr }); } catch (e) {}
        }, 500);
    }

    has(key) {
        const entry = this.cache.get(key);
        if (!entry) return false;

        // Check if expired
        if (Date.now() - entry.ts > this.ttlMs) {
            this.cache.delete(key);
            return false;
        }
        return true;
    }

    add(key) {
        this.cache.set(key, { ts: Date.now() });

        // Cleanup old entries (keep max 500 entries)
        if (this.cache.size > 500) {
            const now = Date.now();
            for (const [k, v] of this.cache.entries()) {
                if (now - v.ts > this.ttlMs) {
                    this.cache.delete(k);
                }
            }
            // If still too large, remove oldest 100 entries
            if (this.cache.size > 500) {
                const entries = [...this.cache.entries()].sort((a, b) => a[1].ts - b[1].ts);
                for (let i = 0; i < 100 && i < entries.length; i++) {
                    this.cache.delete(entries[i][0]);
                }
            }
        }
        this._scheduleSave();
    }

    clear() {
        this.cache.clear();
        this._scheduleSave();
    }
}

export class RuleEngine {
    constructor() {
        this.rules = [];
        this.exclusions = [];
        this.matchedHistory = new Set(); // in-memory only, reset per tab navigation
        this.persistentMatchCache = new MatchCache(30 * 60 * 1000, 'ruleMatchCache'); // 30 min TTL, persisted
        // Per-host dedup for active-probe (fingerprint) rules: once a rule matches
        // any path on a host, further hits on that host are suppressed. Keyed by
        // `${ruleId}|${host}`. Persisted to storage.session so it survives SW restarts.
        this.matchedRuleHosts = new Set();
        this._hostsSaveTimer = null;
        this._loadHosts();
        this.loadRules();
    }

    async _loadHosts() {
        try {
            const data = await chrome.storage.session.get('matchedRuleHosts');
            if (Array.isArray(data.matchedRuleHosts)) {
                data.matchedRuleHosts.forEach(k => this.matchedRuleHosts.add(k));
            }
        } catch (e) {}
    }

    _saveHosts() {
        if (this._hostsSaveTimer) return;
        this._hostsSaveTimer = setTimeout(() => {
            this._hostsSaveTimer = null;
            try { chrome.storage.session.set({ matchedRuleHosts: [...this.matchedRuleHosts] }); } catch (e) {}
        }, 500);
    }

    async loadRules() {
        const data = await chrome.storage.local.get(['rules', 'exclusions']);
        this.rules = data.rules || [];
        this.exclusions = data.exclusions || [];
        // Clean up legacy persistent matchedHistory if present
        chrome.storage.local.remove('matchedHistory');
        console.log('Rules loaded:', this.rules.length);
    }

    /** Reset in-memory match history (call on tab navigation to allow re-matching). */
    resetHistory() {
        this.matchedHistory.clear();
        // NOTE: matchedRuleHosts is intentionally NOT cleared here — a fingerprint
        // identified for a host should stay deduped across in-site navigation.
    }

    /**
     * Whether a rule should be deduped per-host (whole-site framework fingerprint
     * like Shiro) rather than per-path. Explicit `rule.hostDedupe` wins; otherwise
     * default to true only for root-path (`/`) active probes. Path-specific probes
     * (e.g. /actuator/, /xxl-job-admin/toLogin) stay per-path so that nginx reverse
     * proxies mapping different sub-paths to different apps don't lose matches.
     * @param {object} rule
     * @returns {boolean}
     */
    isHostDedupeRule(rule) {
        if (typeof rule.hostDedupe === 'boolean') return rule.hostDedupe;
        if (!rule.probePath) return false;
        const p = String(rule.probePath).trim();
        return p === '/' || p.replace(/^\/+/, '') === '';
    }

    /**
     * Whether a host-dedupe rule has already matched anywhere on a URL's host.
     * @param {string|number} ruleId
     * @param {string} url
     * @returns {boolean}
     */
    hasHostMatch(ruleId, url) {
        try { return this.matchedRuleHosts.has(`${ruleId}|${new URL(url).host}`); }
        catch { return false; }
    }

    /**
     * Check if a rule has already matched a specific URL.
     * @param {string|number} ruleId
     * @param {string} url
     * @returns {boolean}
     */
    isMatched(ruleId, url) {
        if (!ruleId || !url) return false;
        const key = `${ruleId}|${url}`;

        // Check both in-memory history (current session) and persistent cache (cross-refresh)
        return this.matchedHistory.has(key) || this.persistentMatchCache.has(key);
    }

    /**
     * Match content against rules.
     * @param {string} content - The content to check (URL, Header value, or Body).
     * @param {string} type - 'url', 'header', 'body'.
     * @param {object} context - Extra info for logging (tabId, url, etc.).
     * @returns {object[]} - List of matched rules.
     */
    match(content, type, context) {
        // Global Exclusion Check
        // We check context.url (the target URL) against exclusions
        if (context.url && isExcluded(context.url, this.exclusions)) {
            // console.log(`[RuleEngine] Skipped excluded URL: ${context.url}`);
            return [];
        }

        const matches = [];
        for (const rule of this.rules) {
            if (!rule.enabled) continue;

            // Optimization: If already matched, skip checking?
            // User said: "next time match same path... no longer scan match rule".
            // This implies we shouldn't even scan. But if we are here, we are matching.
            // If it's a passive match, we might want to skip alerting.
            // If it's an active match, the scanner should have skipped it.
            // But let's double check here to prevent duplicate alerts for passive rules too.
            if (this.isMatched(rule.id, context.url)) {
                continue;
            }

            // Scope Check Logic:
            // 1. Passive Rules: Must match 'scope' (url, header, body).
            // 2. Active Rules: 
            //    - Normally check 'matchScope' (response_header, body).
            //    - EXCEPTION: If we are checking 'response_header' (from NetworkMonitor), 
            //      we allow Active Rules to match regardless of 'matchScope'. 
            //      This fixes the issue where 'Set-Cookie' is invisible to fetch() (Body scope) 
            //      but captured by NetworkMonitor. We want to catch it if it exists.

            const isActiveRule = !!rule.probePath;
            const isHeaderCheck = type === 'response_header';

            if (isActiveRule) {
                // For active rules checking headers, skip strict scope check to catch Set-Cookie
                if (!isHeaderCheck && rule.matchScope !== type) continue;
            } else {
                // Passive rules strict check
                // 'header' scope in UI maps to 'response_header' type from networkMonitor
                const effectiveScope = rule.scope === 'header' ? 'response_header' : rule.scope;
                if (effectiveScope && effectiveScope !== type) continue;
            }

            let isMatch = false;
            let statusMatch = false;
            let contentMatch = false;

            // 1. Status Code Check (if configured)
            if (rule.matchStatusCode && context.statusCode) {
                // Allow comma separated status codes e.g. "200, 403"
                const allowedCodes = rule.matchStatusCode.split(',').map(c => c.trim());
                statusMatch = allowedCodes.includes(String(context.statusCode));
            } else {
                // If no status code configured, we consider it a "pass" for the status part (or irrelevant)
                // BUT for "OR" logic, if status is not configured, we rely solely on content.
                // For "AND" logic, if status is not configured, we rely solely on content.
                // So effectively, if not configured, statusMatch is true (conceptually).
                statusMatch = true;
            }

            // 2. Content Match
            contentMatch = false; // Initialize contentMatch

            // Optimization: Special handling for empty content matching using ^$
            if (rule.pattern === '^$') {
                contentMatch = !content || content.length === 0;
            } else if (rule.matchType === 'regex') {
                try {
                    const regex = new RegExp(rule.pattern, 'i');
                    contentMatch = regex.test(content);
                } catch (e) {
                    console.error('Invalid Regex:', rule.pattern);
                }
            } else {
                // Simple string match (case insensitive, whitespace normalized)
                const normalizedContent = content.toLowerCase().replace(/\s+/g, ' ');
                const normalizedPattern = rule.pattern.toLowerCase().replace(/\s+/g, ' ');
                contentMatch = normalizedContent.includes(normalizedPattern);
            }

            // 3. Combine Logic
            if (rule.matchStatusCode) {
                if (rule.matchCondition === 'or') {
                    // If either matches
                    // Note: If status code was NOT present in context (e.g. passive URL scan), statusMatch is false?
                    // Wait, if context.statusCode is missing, we can't match status.
                    // So if rule has matchStatusCode, but context has none, statusMatch = false.
                    if (!context.statusCode) statusMatch = false;

                    isMatch = statusMatch || contentMatch;
                } else {
                    // AND (Default)
                    if (!context.statusCode) statusMatch = false; // Must have status code to match it
                    isMatch = statusMatch && contentMatch;
                }
            } else {
                // No status code configured -> Just content match
                isMatch = contentMatch;
            }

            if (isMatch) {
                matches.push(rule);
                this.handleMatch(rule, context);
            }
        }
        return matches;
    }

    handleMatch(rule, context) {
        const matchKey = `${rule.id}|${context.url}`;

        // Double check (though we checked in match loop, handleMatch might be called from Scanner directly)
        if (this.matchedHistory.has(matchKey) || this.persistentMatchCache.has(matchKey)) {
            console.log(`[RuleEngine] Skipping duplicate match: ${matchKey}`);
            return;
        }

        // Per-host dedup for whole-site framework fingerprints (e.g. Shiro): the
        // tech is present on every path, so probing parent dirs would otherwise
        // alert once per directory. Only applies to host-dedupe rules — path-specific
        // rules keep per-URL matching (nginx sub-path reverse proxies stay accurate).
        let hostKey = null;
        if (this.isHostDedupeRule(rule)) {
            try { hostKey = `${rule.id}|${new URL(context.url).host}`; } catch {}
            if (hostKey && this.matchedRuleHosts.has(hostKey)) {
                console.log(`[RuleEngine] Suppressing duplicate host match: ${hostKey} (${context.url})`);
                this.matchedHistory.add(matchKey); // also mark URL so scanner won't re-probe it
                return;
            }
        }

        console.log(`MATCHED Rule [${rule.name}]:`, context);

        // Add to both in-memory history and persistent cache
        this.matchedHistory.add(matchKey);
        this.persistentMatchCache.add(matchKey);
        if (hostKey) { this.matchedRuleHosts.add(hostKey); this._saveHosts(); }

        // Persist log
        addLog(rule.name, context.url, 'match', `Matched rule: ${rule.name}`);

        // Visual Feedback: Badge
        chrome.action.setBadgeText({ text: '1', tabId: context.tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId: context.tabId }); // Mint Green

        // Notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon128.png'),
            title: `Nothing Found: ${rule.name}`,
            message: `Matched in ${context.url}`
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.error('Notification Error:', chrome.runtime.lastError);
            } else {
                console.log('Notification created:', notificationId);
            }
        });

        // Sound (via offscreen document)
        chrome.runtime.sendMessage({ action: 'play_sound', type: 'match' }).catch(err => {
            // Ignore errors if offscreen is not ready or message fails (e.g. popup closed, though offscreen should be there)
            // console.warn('Sound trigger failed:', err);
        });
    }
}

export const ruleEngine = new RuleEngine();

// Listen for rule changes
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.rules || changes.exclusions) {
            ruleEngine.loadRules();
        }
    }
});
