import { addLog } from './logger';
import { isExcluded } from '../utils/exclusionMatcher';
import { matchContent } from './matchHelper';

/**
 * Rule Engine for matching content against user-defined rules.
 */

// ── Match cache (TTL + persistence) ────────────────────────────────────────────
// Persisted to chrome.storage.session so it survives SW restarts (MV3 idle kill).

class MatchCache {
    constructor(ttlMs = 30 * 60 * 1000, persistKey = null) {
        this.cache = new Map();
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
        } catch {}
    }

    _scheduleSave() {
        if (!this.persistKey || this._saveTimer) return;
        this._saveTimer = setTimeout(() => {
            this._saveTimer = null;
            const arr = [...this.cache.entries()].map(([k, v]) => [k, v.ts]);
            try { chrome.storage.session.set({ [this.persistKey]: arr }); } catch {}
        }, 500);
    }

    has(key) {
        const entry = this.cache.get(key);
        if (!entry) return false;
        if (Date.now() - entry.ts > this.ttlMs) {
            this.cache.delete(key);
            return false;
        }
        return true;
    }

    add(key) {
        this.cache.set(key, { ts: Date.now() });
        if (this.cache.size > 500) {
            this._evictExpired();
            if (this.cache.size > 500) this._evictOldest(100);
        }
        this._scheduleSave();
    }

    _evictExpired() {
        const now = Date.now();
        for (const [k, v] of this.cache.entries()) {
            if (now - v.ts > this.ttlMs) this.cache.delete(k);
        }
    }

    _evictOldest(n) {
        const sorted = [...this.cache.entries()].sort((a, b) => a[1].ts - b[1].ts);
        for (let i = 0; i < n && i < sorted.length; i++) this.cache.delete(sorted[i][0]);
    }

    clear() {
        this.cache.clear();
        this._scheduleSave();
    }
}

// ── Rule Engine ────────────────────────────────────────────────────────────────

export class RuleEngine {
    constructor() {
        this.rules = [];
        this.exclusions = [];
        this.matchedHistory = new Set();
        this.persistentMatchCache = new MatchCache(30 * 60 * 1000, 'ruleMatchCache');
        this.matchedRuleHosts = new Set();
        this._hostsSaveTimer = null;

        // Rate-limit notifications: max 1 per (ruleId, tabId) per NOTIFY_COOLDOWN
        this._lastNotifyTime = new Map(); // `${ruleId}|${tabId}` -> timestamp
        this.NOTIFY_COOLDOWN = 10_000;     // 10 seconds

        // Race-condition guard: inflight handleMatch() calls keyed by (ruleId|url)
        this._inflightMatches = new Set();

        this._loadHosts();
        this.loadRules();
    }

    async _loadHosts() {
        try {
            const data = await chrome.storage.session.get('matchedRuleHosts');
            if (Array.isArray(data.matchedRuleHosts)) {
                data.matchedRuleHosts.forEach(k => this.matchedRuleHosts.add(k));
            }
        } catch {}
    }

    _saveHosts() {
        if (this._hostsSaveTimer) return;
        this._hostsSaveTimer = setTimeout(() => {
            this._hostsSaveTimer = null;
            try { chrome.storage.session.set({ matchedRuleHosts: [...this.matchedRuleHosts] }); } catch {}
        }, 500);
    }

    async loadRules() {
        const data = await chrome.storage.local.get(['rules', 'exclusions']);
        this.rules = data.rules || [];
        this.exclusions = data.exclusions || [];
        chrome.storage.local.remove('matchedHistory');
        console.log('Rules loaded:', this.rules.length);
    }

    resetHistory() {
        this.matchedHistory.clear();
    }

    isHostDedupeRule(rule) {
        if (typeof rule.hostDedupe === 'boolean') return rule.hostDedupe;
        if (!rule.probePath) return false;
        const p = String(rule.probePath).trim();
        return p === '/' || p.replace(/^\/+/, '') === '';
    }

    hasHostMatch(ruleId, url) {
        try { return this.matchedRuleHosts.has(`${ruleId}|${new URL(url).host}`); }
        catch { return false; }
    }

    isMatched(ruleId, url) {
        if (!ruleId || !url) return false;
        const key = `${ruleId}|${url}`;
        return this.matchedHistory.has(key)
            || this.persistentMatchCache.has(key)
            || this._inflightMatches.has(key);
    }

    /**
     * Match content against rules.
     * @param {string} content - The content to check (URL, header, or body).
     * @param {string} type   - 'url', 'header', 'body', 'response_header'.
     * @param {object} context - Extra info (tabId, url, type, statusCode).
     * @returns {object[]} - List of matched rules.
     */
    match(content, type, context) {
        if (context.url && isExcluded(context.url, this.exclusions)) {
            return [];
        }

        const matches = [];
        for (const rule of this.rules) {
            if (!rule.enabled) continue;

            const matchKey = `${rule.id}|${context.url}`;
            if (this.isMatched(rule.id, context.url)) continue;

            // ── Scope check ──────────────────────────────────────────────────
            const isActiveRule = !!rule.probePath;
            const isHeaderCheck = type === 'response_header';

            if (isActiveRule) {
                if (!isHeaderCheck && rule.matchScope !== type) continue;
            } else {
                const effectiveScope = rule.scope === 'header' ? 'response_header' : rule.scope;
                if (effectiveScope && effectiveScope !== type) continue;
            }

            // ── Match ─────────────────────────────────────────────────────────
            const { isMatch } = matchContent(rule, content, context.statusCode);
            if (isMatch) {
                matches.push(rule);
                this.handleMatch(rule, context);
            }
        }
        return matches;
    }

    handleMatch(rule, context) {
        const matchKey = `${rule.id}|${context.url}`;

        // Race-condition guard: if another concurrent call is already processing
        // this (rule, url) pair, skip to avoid duplicate notifications.
        if (this._inflightMatches.has(matchKey)) return;
        this._inflightMatches.add(matchKey);

        try {
            if (this.matchedHistory.has(matchKey) || this.persistentMatchCache.has(matchKey)) return;

            // Per-host dedup for whole-site framework fingerprints
            let hostKey = null;
            if (this.isHostDedupeRule(rule)) {
                try { hostKey = `${rule.id}|${new URL(context.url).host}`; } catch {}
                if (hostKey && this.matchedRuleHosts.has(hostKey)) {
                    this.matchedHistory.add(matchKey);
                    return;
                }
            }

            console.log(`MATCHED Rule [${rule.name}]:`, context);

            this.matchedHistory.add(matchKey);
            this.persistentMatchCache.add(matchKey);
            if (hostKey) { this.matchedRuleHosts.add(hostKey); this._saveHosts(); }

            addLog(rule.name, context.url, 'match', `Matched rule: ${rule.name}`);

            // ── Rate-limited notification ────────────────────────────────────
            const notifyKey = `${rule.id}|${context.tabId}`;
            const lastTime = this._lastNotifyTime.get(notifyKey) || 0;
            if (Date.now() - lastTime > this.NOTIFY_COOLDOWN) {
                this._lastNotifyTime.set(notifyKey, Date.now());

                chrome.action.setBadgeText({ text: '1', tabId: context.tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId: context.tabId });

                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: chrome.runtime.getURL('icons/icon128.png'),
                    title: `Nothing Found: ${rule.name}`,
                    message: `Matched in ${context.url}`
                });

                chrome.runtime.sendMessage({ action: 'play_sound', type: 'match' }).catch(() => {});
            } else {
                // Still update the badge (don't flash notify but keep the indicator)
                chrome.action.setBadgeText({ text: '1', tabId: context.tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId: context.tabId });
            }
        } finally {
            this._inflightMatches.delete(matchKey);
        }
    }
}

export const ruleEngine = new RuleEngine();

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.rules || changes.exclusions) {
            ruleEngine.loadRules();
        }
    }
});
