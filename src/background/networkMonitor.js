import { activeScanner } from './scanner';
import { ruleEngine } from './ruleEngine';
import { detectFingerprints, detectAnalyticsFromUrl } from './fingerprint';
import { pendingProbes } from './probeRegistry';
import { addLog } from './logger';
import { matchContent } from './matchHelper';

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
                if (pendingProbes.has(details.url)) {
                    const { rule, tabId } = pendingProbes.get(details.url);
                    pendingProbes.delete(details.url);

                    if (rule.matchScope === 'response_header') {
                        const headerString = (details.responseHeaders || [])
                            .map(h => `${h.name}: ${h.value}`).join('\n');

                        const { isMatch, statusMatch, contentMatch } = matchContent(rule, headerString, details.statusCode);
                        console.log(`[NetworkMonitor] Probe header match for ${details.url}: statusMatch=${statusMatch}, contentMatch=${contentMatch}`);
                        if (isMatch) {
                            ruleEngine.handleMatch(rule, { tabId, url: details.url, type: 'active-probe-header', statusCode: details.statusCode });
                            addLog(rule.name, details.url, 'match', 'Pattern found in Response Headers (active probe)');
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

                // Build header string for passive rule matching
                const headerString = (details.responseHeaders || [])
                    .map(h => `${h.name}: ${h.value}`).join('\n');

                ruleEngine.match(headerString, 'response_header', {
                    tabId: details.tabId,
                    url: details.url,
                    type: 'response_header',
                    statusCode: details.statusCode,
                });
            },
            { urls: ['<all_urls>'] },
            ['responseHeaders', 'extraHeaders']
        );

        console.log('[NetworkMonitor] Started');
    }
}

export const networkMonitor = new NetworkMonitor();
