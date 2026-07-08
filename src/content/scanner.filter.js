// Scanner filter functions - exposed as window.SCANNER_FILTER
window.SCANNER_FILTER = {
    // IP whitelist - skip private/loopback ranges
    isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return false;
        if (parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
        const [a, b] = parts;
        return (
            a === 10 ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            a === 127 ||
            a === 0 ||
            (a === 169 && b === 254) ||       // link-local
            (a === 100 && b >= 64 && b <= 127) // CGNAT
        );
    },

    // Filter out boring/static file paths
    isBoringPath(path) {
        if (!path) return true;
        const boring = [
            /\.(png|jpg|jpeg|gif|bmp|webp|svg|ico|mp3|mp4|m4a|wav|swf)(\?.*)?$/i,
            /\.(ttf|eot|woff|woff2|otf|css|less)(\?.*)?$/i,
            /\.(js|jsx|ts|tsx)(\?.*)?$/i,
            /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|exe|apk|dmg)(\?.*)?$/i,
            /^\/static\//,
            /^\/assets\//,
            /^\/public\//,
            /^(audio|blots|core|ace|icon|css|formats|image|js|modules|text|themes|ui|video|static|attributors|application)\//i,
            // data-URI / SVG / URL-encoded markup junk (e.g. "/%3e%3cpath class=")
            /[<>]/,
            /%3c|%3e|%22|%27|%20class/i,
            /^data:/i,
            /^\/?(?:M-?\d|[MmLlHhVvCcSsQqTtAaZz]\s?-?\d)/, // SVG path data (starts with move/line cmd)
        ];
        if (boring.some(r => r.test(path))) return true;
        // Filter very short paths
        if (path.replace(/^\//, '').length <= 3) return true;
        return false;
    },

    // Junk resource URLs/srcs that pollute results (data-URIs, extension internals,
    // SVG namespace, build assets, encoded markup).
    isJunkResource(val) {
        if (!val) return true;
        return /^(?:data:|blob:|javascript:|about:|chrome-extension:|moz-extension:)/i.test(val)
            || /w3\.org|\.w3\.org/i.test(val)
            || /%3c|%3e|[<>]/i.test(val)
            || /^https?:\/\/(?:localhost|127\.0\.0\.1)/i.test(val);
    },

    // Decode the few HTML entities that leak into scanned attribute values.
    decodeEntities(s) {
        return s ? s.replace(/&amp;/g, '&').replace(/&#x2f;/gi, '/').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)) : s;
    },

    // Normalize an API path for dedup: strip query VALUES but keep keys, so many
    // "/x?id=1", "/x?id=2"… collapse to a single "/x?id" entry (kills param floods).
    normalizeApiPath(path) {
        const qIdx = path.indexOf('?');
        if (qIdx === -1) return path;
        const base = path.slice(0, qIdx);
        const query = path.slice(qIdx + 1);
        const keys = [...new Set(query.split(/[&;]/).map(kv => kv.split('=')[0]).filter(Boolean))];
        return keys.length ? `${base}?${keys.join('&')}` : base;
    },

    // Deduplicate results
    dedupe(arr) {
        return [...new Set(arr)];
    },

    // Truncate long values for display
    truncate(str, max = 120) {
        if (!str) return '';
        return str.length > max ? str.slice(0, max) + '…' : str;
    },

    // Check if a string looks like a real secret (not a placeholder)
    isRealSecret(val) {
        if (!val) return false;
        // 明确的占位符/示例值
        const placeholders = /^(your|example|test|demo|placeholder|xxx|abc|123|null|undefined|false|true|none|empty|default|sample|foo|bar|baz|changeme|change_me|change|reset|please|confirm|original|current|new|old|input|enter)$/i;
        if (placeholders.test(val)) return false;
        // 太短
        if (val.length < 8) return false;
        // 纯中文 UI 提示文本（含中文字符）
        if (/[\u4e00-\u9fff]/.test(val)) return false;
        // 以大写字母开头且全是可读单词（UI label 特征）
        if (/^[A-Z][a-zA-Z\s]{4,}$/.test(val)) return false;
        // 值看起来是变量名/属性名（camelCase 或 snake_case，无特殊字符）
        if (/^[a-zA-Z][a-zA-Z0-9_]{3,}$/.test(val) && !/[^a-zA-Z0-9_]/.test(val) && val.length < 20) return false;
        // authorization 字段值是对象展开表达式（含 e. 前缀）
        if (/^e\.[a-zA-Z]/.test(val)) return false;
        // 值是 JS 对象属性链（如 e.authorization,displayType...）
        if (/[a-z]\.[a-zA-Z]/.test(val) && val.includes(',')) return false;
        // 必须包含至少一个数字或特殊字符，纯字母可读词组不算密钥
        const hasEntropy = /[0-9!@#$%^&*\-_+=\/\\]/.test(val);
        if (!hasEntropy) return false;
        return true;
    },
};
