// Scanner configuration - exposed as window.SCANNER_CONFIG
window.SCANNER_CONFIG = {
    // API endpoints (absolute + relative paths)
    api: {
        name: 'API Endpoint',
        patterns: [
            /['"`](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\}\,\'\"\\](?:[^\^\>\< \)\(\,\'\"\\])*?['"`]|['"`][a-zA-Z0-9]+(?<!text|application)\/(?:[^\^\>\< \)\(\{\}\,\'\"\\])*?["'`]/g,
        ]
    },
    // IP addresses — strict octets (NO leading zeros, so SVG coords / minified
    // numeric junk like "04.04.06.05" or "007.022.018.041" no longer match).
    ip: {
        name: 'IP Address',
        patterns: [
            /\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/g,
            /\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b/g,
        ]
    },
    // Credentials / secrets
    credential: {
        name: 'Credential / Secret',
        patterns: [
            /["'`]?(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["'`]([^"'`\s]{4,})/gi,
            /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/g,
            /Authorization\s*:\s*["'`]?([^\s"'`]{8,})/gi,
        ]
    },
    // JWT tokens
    jwt: {
        name: 'JWT Token',
        patterns: [
            /\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*)\b/g,
        ]
    },
    // ID Keys / Cloud Keys (specific high-confidence patterns only)
    idKey: {
        name: 'ID Key',
        patterns: [
            /\bwx[a-z0-9]{15,18}\b/g,                                         // WeChat AppID
            /\bLTAI[A-Za-z\d]{12,30}\b/g,                                     // Alibaba Cloud
            /\bAIza[0-9A-Za-z_\-]{35}\b/g,                                    // Google API Key
            /\bAKID[A-Za-z\d]{13,40}\b/g,                                     // Tencent Cloud
            /\bAKIA[0-9A-Z]{16}\b/g,                                          // AWS Access Key
            /\bASIA[0-9A-Z]{16}\b/g,                                          // AWS Temp Key
            /\bglpat-[a-zA-Z0-9\-=_]{20,22}\b/g,                             // GitLab Token
            /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,100}\b/g, // GitHub Token
            /\b(?:sk|pk)_live_[0-9a-zA-Z]{24,}\b/g,                           // Stripe Live Key
            /\bww[a-z0-9]{15,18}\b/g,                                         // Enterprise WeChat
            /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,                                // Anthropic API Key
            /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,                 // OpenAI API Key
            /\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b/g,                           // Slack Token
            /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,                // SendGrid Key
            /\bSK[0-9a-fA-F]{32}\b/g,                                         // Twilio Key
            /\bnpm_[A-Za-z0-9]{36}\b/g,                                       // npm Token
            /\bAPPCODE\s+[0-9a-f]{32}\b/g,                                    // Aliyun APPCODE
            /\bJDCLOUD[0-9A-Z]{20,32}\b/g,                                    // JD Cloud
        ]
    },
    // Chinese ID card numbers (PII)
    idcard: {
        name: 'ID Card',
        patterns: [
            /\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
        ]
    },
    // Phone numbers (CN)
    phone: {
        name: 'Phone Number',
        patterns: [
            /\b(1[3-9]\d{9})\b/g,
        ]
    },
    // Email addresses
    email: {
        name: 'Email Address',
        patterns: [
            /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g,
        ]
    },
    // Document / installer / archive files (downloadable artifacts).
    // MUST contain a path separator ('/') so bare filename tokens like "pf.conf"
    // (config-name references, not downloadable files) are not flagged.
    docFile: {
        name: 'Document File',
        patterns: [
            /["'`]([^"'`\s]*\/[^"'`\s]*?\.(?:exe|msi|apk|dmg|pkg|doc|docx|xls|xlsx|ppt|pptx|pdf|rtf|zip|rar|7z|tar|gz|tgz|sql|bak))(?:\?[^"'`\s]*)?["'`]/gi,
        ]
    },
    // Internal paths / file paths
    path: {
        name: 'Internal Path',
        patterns: [
            /["'`](\/(?:etc|var|usr|home|root|tmp|opt|proc|sys)\/[^\s"'`]{3,})/g,
            /["'`]([A-Za-z]:\\[^\s"'`]{2,})/g,
        ]
    },
    // Absolute URLs
    url: {
        name: 'URL',
        patterns: [
            /(?:https?|wss?|ftp):\/\/(?:(?:[\w-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?(?:\/[^\s\>\)\}\<'"]{3,})?/gi,
        ]
    },
};
