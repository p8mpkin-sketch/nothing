import { activeScanner } from './scanner';
import { detectFingerprints, detectAnalyticsFromUrl } from './fingerprint';
import { pendingProbes } from './probeRegistry';

// tabJsMap: tabId -> Set<url> (JS request URLs)
export const tabJsMap = {};
// tabFingerprints: tabId -> { server:[], os:[], technology:[], framework:[], security:[], cdn:[], analytics:[] }
export const tabFingerprints = {};

function mergeFingerprints(tabId, detected) {
    if (!tabFingerprints[tabId]) tabFingerprints[tabId] = {};
    for (const [cat, items] of Object.entries(detected)) {
        if (!tabFingerprints[tabId][cat]) tabFingerprints[tabId][cat] = [];
        for (const item of items) {
            if (!tabFingerprints[tabId][cat].find(x => x.name === item.name)) {
                tabFingerprints[tabId][cat].push(item);
            }
        }
    }
}

function addAnalytics(tabId, name) {
    if (!tabFingerprints[tabId]) tabFingerprints[tabId] = {};
    if (!tabFingerprints[tabId].analytics) tabFingerprints[tabId].analytics = [];
    if (!tabFingerprints[tabId].analytics.find(x => x.name === name)) {
        tabFingerprints[tabId].analytics.push({ name, value: '' });
    }
}

export class NetworkMonitor {
    constructor() {
        this.start();
    }

    start() {
        // Track JS URLs and analytics per tab
        chrome.webRequest.onCompleted.addListener(
            (details) => {
                if (details.tabId === -1) return;
                if (!details.url.startsWith('http')) return;

                // Record JS URLs
                if (details.type === 'script') {
                    if (!tabJsMap[details.tabId]) tabJsMap[details.tabId] = new Set();
                    tabJsMap[details.tabId].add(details.url);
                }

                // Detect analytics from URL
                const analyticsName = detectAnalyticsFromUrl(details.url);
                if (analyticsName) {
                    addAnalytics(details.tabId, analyticsName);
                }

                // Active scanner
                activeScanner.scan(details.url, details.tabId);
            },
            { urls: ['<all_urls>'] }
        );

        // Capture response headers for fingerprinting and rule matching
        chrome.webRequest.onHeadersReceived.addListener(
            (details) => {
                // Active probe header matching FIRST — service-worker fetch() shows up
                // with tabId === -1, so this must run before the tabId guard below.
                // Uses 'extraHeaders' so it CAN read Set-Cookie (fetch() cannot).
                if (pendingProbes.has(details.url)) {
                    const { rule, tabId } = pendingProbes.get(details.url);
                    pendingProbes.delete(details.url);

                    if (rule.matchScope === 'response_header') {
                        const headerString = (details.responseHeaders || [])
                            .map(h => `${h.name}: ${h.value}`).join('\n');
                        console.log(`[NetworkMonitor] Probe headers for ${details.url}:`, headerString);

                        const statusMatch = rule.matchStatusCode
                            ? rule.matchStatusCode.split(',').map(c => c.trim()).includes(String(details.statusCode))
                            : true;
                        let contentMatch = false;
                        if (rule.pattern === '^$') {
                            contentMatch = !headerString || headerString.length === 0;
                        } else if (rule.matchType === 'regex') {
                            try { contentMatch = new RegExp(rule.pattern, 'i').test(headerString); } catch {}
                        } else {
                            contentMatch = headerString.toLowerCase().replace(/\s+/g, ' ')
                                .includes(rule.pattern.toLowerCase().replace(/\s+/g, ' '));
                        }
                        const isMatch = rule.matchStatusCode
                            ? (rule.matchCondition === 'or' ? (statusMatch || contentMatch) : (statusMatch && contentMatch))
                            : contentMatch;

                        console.log(`[NetworkMonitor] Probe header match for ${details.url}: statusMatch=${statusMatch}, contentMatch=${contentMatch}`);
                        if (isMatch) {
                            import('./ruleEngine').then(({ ruleEngine }) => {
                                ruleEngine.handleMatch(rule, { tabId, url: details.url, type: 'active-probe-header', statusCode: details.statusCode });
                            });
                            import('./logger').then(({ addLog }) => {
                                addLog(rule.name, details.url, 'match', 'Pattern found in Response Headers (active probe)');
                            });
                        }
                    }
                }

                if (details.tabId === -1) return;

                // Fingerprint detection from headers
                if (details.responseHeaders) {
                    const detected = detectFingerprints(details.responseHeaders);
                    if (Object.keys(detected).length > 0) {
                        mergeFingerprints(details.tabId, detected);
                    }
                }

                // Build header string
                const headerList = [];
                if (details.responseHeaders) {
                    details.responseHeaders.forEach(h => {
                        headerList.push(`${h.name}: ${h.value}`);
                    });
                }
                const headerString = headerList.join('\n');

                // Passive rule matching (active-probe matching handled above the guard)
                import('./ruleEngine').then(({ ruleEngine }) => {
                    ruleEngine.match(headerString, 'response_header', {
                        tabId: details.tabId,
                        url: details.url,
                        type: 'response_header',
                        statusCode: details.statusCode,
                    });
                });
            },
            { urls: ['<all_urls>'] },
            ['responseHeaders', 'extraHeaders']
        );

        console.log('[NetworkMonitor] Started');
    }
}

export const networkMonitor = new NetworkMonitor();
