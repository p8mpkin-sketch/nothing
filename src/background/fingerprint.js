export const FINGERPRINT_CONFIG = {
    server: [
        { name: 'Nginx', header: 'server', pattern: /nginx\/?([\d.]+)?/i },
        { name: 'Apache', header: 'server', pattern: /apache\/?([\d.]+)?/i },
        { name: 'IIS', header: 'server', pattern: /microsoft-iis\/?([\d.]+)?/i },
        { name: 'Tomcat', header: 'server', pattern: /(?:apache-coyote|tomcat)\/?([\d.]+)?/i },
        { name: 'Caddy', header: 'server', pattern: /caddy\/?([\d.]+)?/i },
        { name: 'LiteSpeed', header: 'server', pattern: /litespeed/i },
        { name: 'OpenResty', header: 'server', pattern: /openresty\/?([\d.]+)?/i },
        { name: 'Tengine', header: 'server', pattern: /tengine\/?([\d.]+)?/i },
        { name: 'Gunicorn', header: 'server', pattern: /gunicorn\/?([\d.]+)?/i },
        { name: 'Kestrel', header: 'server', pattern: /kestrel/i },
        { name: 'Jetty', header: 'server', pattern: /jetty\/?\(?([\d.]+)?/i },
        { name: 'Werkzeug', header: 'server', pattern: /werkzeug\/?([\d.]+)?/i },
        { name: 'WebLogic', header: 'server', pattern: /weblogic/i },
        { name: 'BWS (百度)', header: 'server', pattern: /bws\/?([\d.]+)?/i },
    ],
    os: [
        { name: 'Ubuntu', header: 'server', pattern: /ubuntu/i },
        { name: 'Debian', header: 'server', pattern: /debian/i },
        { name: 'CentOS', header: 'server', pattern: /centos/i },
        { name: 'Windows Server', header: 'server', pattern: /win/i },
        { name: 'FreeBSD', header: 'server', pattern: /freebsd/i },
    ],
    technology: [
        { name: 'PHP', header: 'x-powered-by', pattern: /php\/?([\d.]+)?/i },
        { name: 'ASP.NET', header: 'x-powered-by', pattern: /asp\.net/i },
        { name: 'ASP.NET', header: 'x-aspnet-version', pattern: /([\d.]+)/i },
        { name: 'ASP.NET MVC', header: 'x-aspnetmvc-version', pattern: /([\d.]+)/i },
        { name: 'Express', header: 'x-powered-by', pattern: /express/i },
        { name: 'Next.js', header: 'x-powered-by', pattern: /next\.js/i },
        { name: 'Java', header: 'x-powered-by', pattern: /java|servlet/i },
        { name: 'Python', header: 'x-powered-by', pattern: /python/i },
        { name: 'Ruby', header: 'x-powered-by', pattern: /ruby|phusion/i },
        { name: 'Node.js', header: 'x-powered-by', pattern: /node/i },
        { name: 'Spring Boot (Actuator)', header: 'x-application-context', pattern: /.+/ },
        { name: 'Jenkins', header: 'x-jenkins', pattern: /([\d.]+)?/i },
        { name: 'GitLab', header: 'x-gitlab-feature-category', pattern: /.+/ },
        { name: 'Kong Gateway', header: 'via', pattern: /kong\/?([\d.]+)?/i },
        { name: 'APISIX', header: 'server', pattern: /apisix\/?([\d.]+)?/i },
    ],
    framework: [
        { name: 'Laravel', header: 'set-cookie', pattern: /laravel_session/i },
        { name: 'Django', header: 'set-cookie', pattern: /csrftoken|django/i },
        { name: 'Rails', header: 'set-cookie', pattern: /_rails_session/i },
        { name: 'Spring', header: 'set-cookie', pattern: /jsessionid/i },
        { name: 'WordPress', header: 'set-cookie', pattern: /wordpress_|wp-settings/i },
        { name: 'Drupal', header: 'set-cookie', pattern: /drupal/i },
        { name: 'Joomla', header: 'set-cookie', pattern: /joomla/i },
        { name: 'ASP.NET', header: 'set-cookie', pattern: /asp\.net_sessionid|\.aspxauth/i },
        { name: 'Shiro', header: 'set-cookie', pattern: /rememberme/i },
    ],
    security: [
        { name: 'HSTS', header: 'strict-transport-security', pattern: /.+/ },
        { name: 'CSP', header: 'content-security-policy', pattern: /.+/ },
        { name: 'X-Frame-Options', header: 'x-frame-options', pattern: /.+/ },
        { name: 'X-XSS-Protection', header: 'x-xss-protection', pattern: /.+/ },
        { name: 'CORS', header: 'access-control-allow-origin', pattern: /.+/ },
        { name: 'WAF (Cloudflare)', header: 'cf-ray', pattern: /.+/ },
        { name: 'WAF (AWS)', header: 'x-amzn-requestid', pattern: /.+/ },
    ],
    analytics: [
        { name: 'Google Analytics', header: null, urlPattern: /google-analytics\.com|gtag\/js|analytics\.js/i },
        { name: 'Baidu Analytics', header: null, urlPattern: /hm\.baidu\.com/i },
        { name: 'Matomo', header: null, urlPattern: /matomo\.js|piwik\.js/i },
        { name: 'Hotjar', header: null, urlPattern: /hotjar\.com/i },
    ],
    cdn: [
        { name: 'Cloudflare', header: 'cf-ray', pattern: /.+/ },
        { name: 'Cloudflare', header: 'server', pattern: /cloudflare/i },
        { name: 'Fastly', header: 'x-served-by', pattern: /cache/i },
        { name: 'Akamai', header: 'x-check-cacheable', pattern: /.+/ },
        { name: 'AWS CloudFront', header: 'x-amz-cf-id', pattern: /.+/ },
        { name: 'Alibaba CDN', header: 'via', pattern: /alicdn|aliyun/i },
        { name: 'Tencent CDN', header: 'x-cache', pattern: /tencent|qcloud/i },
    ],
    builder: [
        { name: 'WordPress', header: 'link', pattern: /wp-json|wp-content/i },
        { name: 'Shopify', header: 'x-shopify-stage', pattern: /.+/ },
        { name: 'Wix', header: 'x-wix-request-id', pattern: /.+/ },
    ],
};

/**
 * Parse response headers array into a map (lowercase keys)
 * @param {Array} headersArray - [{name, value}]
 * @returns {Object} map of lowercase header name -> value
 */
export function parseHeaders(headersArray) {
    const map = {};
    if (!headersArray) return map;
    for (const h of headersArray) {
        map[h.name.toLowerCase()] = h.value;
    }
    return map;
}

/**
 * Detect fingerprints from response headers
 * @param {Array} headersArray - [{name, value}]
 * @returns {Object} category -> [{name, value}]
 */
export function detectFingerprints(headersArray) {
    const headers = parseHeaders(headersArray);
    const result = {};

    for (const [category, rules] of Object.entries(FINGERPRINT_CONFIG)) {
        if (category === 'analytics') continue; // analytics detected via URL
        for (const rule of rules) {
            if (!rule.header) continue;
            const val = headers[rule.header];
            if (!val) continue;
            const m = val.match(rule.pattern);
            if (!m) continue;
            if (!result[category]) result[category] = [];
            // Skip if this base signature was already recorded (dedupe by rule name)
            if (result[category].find(r => r._base === rule.name)) continue;
            // Extract a version from capture group 1 when present
            const version = (m[1] && /[\d]/.test(m[1])) ? m[1] : '';
            result[category].push({
                _base: rule.name,
                name: version ? `${rule.name} ${version}` : rule.name,
                value: val,
            });
        }
    }

    return result;
}

/**
 * Detect analytics from a request URL
 * @param {string} url
 * @returns {string|null} analytics name or null
 */
export function detectAnalyticsFromUrl(url) {
    for (const rule of FINGERPRINT_CONFIG.analytics) {
        if (rule.urlPattern && rule.urlPattern.test(url)) {
            return rule.name;
        }
    }
    return null;
}
