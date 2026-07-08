

/**
 * Check if a hostname matches a wildcard pattern.
 * e.g. *.google.com matches mail.google.com
 */
function matchWildcard(hostname, pattern) {
    if (pattern === hostname) return true;

    // Escape special regex chars except *
    const escapeRegex = (str) => str.replace(/([.+?^=!:${}()|\[\]\/\\])/g, "\\$1");

    // Convert wildcard to regex
    // *.google.com -> .*\.google\.com$
    // * -> .*
    const regexStr = "^" + pattern.split("*").map(escapeRegex).join(".*") + "$";
    const regex = new RegExp(regexStr);
    return regex.test(hostname);
}

/**
 * Convert IP string to long number
 */
function ipToLong(ip) {
    let parts = ip.split('.');
    if (parts.length !== 4) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Check if IP is in CIDR range
 * e.g. 192.168.0.1 in 192.168.0.0/24
 */
function matchCIDR(ip, cidr) {
    const [range, bits] = cidr.split('/');
    if (!range || !bits) return false;

    const mask = ~((1 << (32 - parseInt(bits))) - 1);
    const ipLong = ipToLong(ip);
    const rangeLong = ipToLong(range);

    if (ipLong === null || rangeLong === null) return false;

    return (ipLong & mask) === (rangeLong & mask);
}

/**
 * Check if a URL should be excluded based on the list of exclusion rules.
 * @param {string} urlStr 
 * @param {string[]} exclusions 
 */
export function isExcluded(urlStr, exclusions) {
    if (!exclusions || exclusions.length === 0) return false;

    try {
        const url = new URL(urlStr);
        const hostname = url.hostname;

        for (const rule of exclusions) {
            // Handle both string and object formats {id, value}
            const ruleValue = typeof rule === 'string' ? rule : rule?.value;
            if (!ruleValue) continue;

            const cleanRule = ruleValue.trim();
            if (!cleanRule) continue;

            // Check if rule is CIDR (contains / and is likely IP)
            // Simple check: starts with digit and contains /
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cleanRule)) {
                // It's a CIDR
                // Check if hostname is an IP
                if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
                    if (matchCIDR(hostname, cleanRule)) return true;
                }
                // If hostname is not IP (e.g. google.com), it won't match CIDR
            } else {
                // Domain wildcard match
                if (matchWildcard(hostname, cleanRule)) return true;
            }
        }
    } catch (e) {
        console.error('Exclusion check error:', e);
    }
    return false;
}
