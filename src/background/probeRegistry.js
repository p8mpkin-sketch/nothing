// Shared registry for active probe URLs waiting for response headers via webRequest
// url -> { rule, tabId }
export const pendingProbes = new Map();
