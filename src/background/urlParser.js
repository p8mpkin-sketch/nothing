/**
 * Parses a URL and returns a list of parent directory URLs.
 * Example: https://example.com/a/b/c ->
 * [
 *   "https://example.com/a/b/",
 *   "https://example.com/a/",
 *   "https://example.com/"
 * ]
 * @param {string} urlStr
 * @returns {string[]}
 */

// Static file extensions to skip as directory segments
const STATIC_EXTS = new Set([
    'ico','jpg','jpeg','png','gif','webp','svg','bmp',
    'css','woff','woff2','ttf','eot','otf',
    'mp3','mp4','wav','ogg','webm',
    'pdf','zip','gz','tar','rar',
    'map','min.js','js'
]);

// Static resource path patterns (not API/web app paths)
const STATIC_PATH_PATTERNS = [
    /^assets?\b/i,
    /^static\b/i,
    /^js\b/i,
    /^css\b/i,
    /^img(ages?)?\b/i,
    /^images?\b/i,
    /^fonts?\b/i,
    /^media\b/i,
    /^resources?\b/i,
    /^public\b/i,
    /^dist\b/i,
    /^build\b/i,
    /^vendor\b/i,
    /^lib(rary)?\b/i,
    /^node_modules\b/i,
    /^bower_components\b/i,
    /\.(css|js|jpg|jpeg|png|gif|svg|woff2?|ttf|eot|ico|map)$/i,
];

function isStaticFile(part) {
    const dot = part.lastIndexOf('.');
    if (dot === -1) return false;
    const ext = part.slice(dot + 1).toLowerCase();
    return STATIC_EXTS.has(ext);
}

function isStaticPath(part) {
    // Check if path segment matches static resource patterns
    return STATIC_PATH_PATTERNS.some(pattern => pattern.test(part));
}

export function getParentHierarchies(urlStr) {
    try {
        const url = new URL(urlStr);
        const paths = [];

        // Ignore non-http(s) protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return [];
        }

        let pathname = url.pathname;

        // Split by slash, filter empty
        const parts = pathname.split('/').filter(p => p.length > 0);

        // Construct parents
        let currentPath = '/';
        paths.push(url.origin + currentPath); // Root

        for (let i = 0; i < parts.length; i++) {
            const part = parts[i];

            // Skip if it's the last part and is a static file
            if (i === parts.length - 1 && isStaticFile(part)) {
                continue;
            }

            // Skip if this path segment is a static resource directory
            if (isStaticPath(part)) {
                continue;
            }

            currentPath += part + '/';
            paths.push(url.origin + currentPath);
        }

        // Return unique list, deepest first
        return [...new Set(paths)].sort((a, b) => b.length - a.length);
    } catch (e) {
        console.error('Invalid URL', urlStr);
        return [];
    }
}
