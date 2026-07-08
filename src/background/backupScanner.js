import { addLog } from './logger';

/**
 * Backup File & Sensitive File Scanner
 * 扫描备份文件、版本控制泄露等敏感文件
 */

// 精简的高命中率备份文件扩展名（只保留最常见的）
const BACKUP_EXTENSIONS = [
    // 最常见压缩包（命中率 > 80%）
    '.zip', '.rar', '.tar.gz', '.tar',

    // 最常见备份后缀（命中率 > 60%）
    '.bak', '.tmp',
];

// 精简的备份文件名（只保留最常见的）
const BACKUP_NAMES = [
    'www', 'web', 'backup', 'bak', 'wwwroot', 'site',
];

// 版本控制泄露路径（只保留最常见的）
const VCS_PATHS = [
    '.svn/entries',
    '.svn/wc.db',
];

// 精简的敏感文件（只保留高价值目标）
const SENSITIVE_FILES = [
    // 配置文件（高价值）
    '.env',
];

export class BackupScanner {
    constructor() {
        this.enabled = false;
        this.scannedPaths = new Map(); // hostname -> Set<path>
        this.scannedTimestamps = new Map(); // path -> timestamp
        this.scanTTL = 30 * 60 * 1000; // 30 minutes
        this.maxConcurrent = 10; // 最大并发请求数（提升速度）
        this.requestDelay = 50; // 请求间隔（毫秒）（减少延迟）
        this.findings = new Map(); // tabId -> findings[]
        this.findingsHistory = new Map(); // hostname -> findings[] (持久化历史)
        this.scanStatus = new Map(); // tabId -> { status, progress, total, scanned }
        this.loadSettings();
    }

    async loadSettings() {
        const data = await chrome.storage.local.get(['settings']);
        this.enabled = data.settings?.backupScan || false;
        console.log('[BackupScanner] enabled:', this.enabled);
    }

    /**
     * 获取扫描状态
     */
    getStatus(tabId) {
        return this.scanStatus.get(tabId) || { status: 'idle', progress: 0, total: 0, scanned: 0 };
    }

    /**
     * 更新扫描状态
     */
    updateStatus(tabId, status, scanned = 0, total = 0) {
        const progress = total > 0 ? Math.round((scanned / total) * 100) : 0;
        this.scanStatus.set(tabId, { status, progress, total, scanned });

        // 通知 popup 更新状态
        chrome.runtime.sendMessage({
            action: 'BACKUP_STATUS',
            tabId,
            status: { status, progress, total, scanned },
        }).catch(() => {});
    }

    /**
     * 生成扫描字典
     * @param {string} url - 当前页面 URL
     * @returns {object} - { root: [], subdirs: [], vcs: [], sensitive: [] }
     */
    generateDictionary(url) {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const pathname = urlObj.pathname;

        const dict = {
            root: [],      // 根目录备份文件
            subdirs: [],   // 子目录备份文件
            vcs: [],       // 版本控制泄露
            sensitive: [], // 敏感文件
        };

        // 1. 根据域名/子域名生成根目录字典
        const domainParts = hostname.split('.');
        const subdomain = domainParts.length > 2 ? domainParts[0] : null;

        // 常见名称 + 扩展名
        for (const name of BACKUP_NAMES) {
            for (const ext of BACKUP_EXTENSIONS) {
                dict.root.push(`/${name}${ext}`);
            }
        }

        // 子域名 + 扩展名（跳过，避免生成 101.zip 等无意义路径）
        // if (subdomain && subdomain !== 'www') {
        //     for (const ext of BACKUP_EXTENSIONS) {
        //         dict.root.push(`/${subdomain}${ext}`);
        //     }
        // }

        // 主域名 + 扩展名（跳过，避免生成无意义路径）
        // const mainDomain = domainParts.length > 1 ? domainParts[domainParts.length - 2] : hostname;
        // for (const ext of BACKUP_EXTENSIONS) {
        //     dict.root.push(`/${mainDomain}${ext}`);
        // }

        // 2. 根据当前路径提取子目录
        const pathSegments = pathname.split('/').filter(s => s.length > 0);
        const subdirs = new Set();

        // 提取所有层级的目录
        for (let i = 0; i < pathSegments.length; i++) {
            const segment = pathSegments[i];
            // 跳过文件名（包含扩展名）
            if (segment.includes('.') && i === pathSegments.length - 1) continue;

            subdirs.add(segment);

            // 构建完整路径
            const fullPath = '/' + pathSegments.slice(0, i + 1).join('/');
            subdirs.add(fullPath);
        }

        // 常见子目录名称（大幅精简）
        const commonSubdirs = [
            'admin', 'api', 'upload', 'uploads', 'backup', 'data',
        ];

        for (const dir of commonSubdirs) {
            subdirs.add(`/${dir}`);
        }

        // 为每个子目录生成备份文件字典
        for (const dir of subdirs) {
            const dirName = dir.split('/').filter(s => s).pop();
            if (!dirName) continue;

            for (const ext of BACKUP_EXTENSIONS) {
                // /js/js.zip
                dict.subdirs.push(`${dir}/${dirName}${ext}`);
                // /js.zip
                dict.subdirs.push(`/${dirName}${ext}`);
            }

            // 常见备份名称
            for (const name of ['backup', 'bak', 'old', 'temp']) {
                for (const ext of ['.zip', '.tar.gz', '.rar', '.7z']) {
                    dict.subdirs.push(`${dir}/${name}${ext}`);
                }
            }
        }

        // 3. 版本控制泄露（只扫描根目录，不扫描子目录）
        for (const vcsPath of VCS_PATHS) {
            dict.vcs.push(`/${vcsPath}`);
        }

        // 4. 敏感文件（只扫描根目录，不扫描子目录）
        for (const file of SENSITIVE_FILES) {
            dict.sensitive.push(`/${file}`);
        }

        // 去重
        dict.root = [...new Set(dict.root)];
        dict.subdirs = [...new Set(dict.subdirs)];
        dict.vcs = [...new Set(dict.vcs)];
        dict.sensitive = [...new Set(dict.sensitive)];

        return dict;
    }

    /**
     * 扫描入口
     * @param {string} currentUrl - 当前页面 URL
     * @param {number} tabId - Tab ID
     */
    async scan(currentUrl, tabId) {
        await this.loadSettings();

        if (!this.enabled) {
            console.log('[BackupScanner] Disabled, skipping scan');
            this.updateStatus(tabId, 'disabled', 0, 0);
            return;
        }

        console.log('[BackupScanner] Starting scan for:', currentUrl);
        this.updateStatus(tabId, 'scanning', 0, 0);

        try {
            const urlObj = new URL(currentUrl);
            const origin = urlObj.origin;
            const hostname = urlObj.hostname;

            // 初始化扫描历史
            if (!this.scannedPaths.has(hostname)) {
                this.scannedPaths.set(hostname, new Set());
            }
            const hostScanned = this.scannedPaths.get(hostname);

            // 生成字典
            const dict = this.generateDictionary(currentUrl);
            console.log('[BackupScanner] Generated dictionary:', {
                root: dict.root.length,
                subdirs: dict.subdirs.length,
                vcs: dict.vcs.length,
                sensitive: dict.sensitive.length
            });
            console.log('[BackupScanner] Sample root paths:', dict.root.slice(0, 10));
            console.log('[BackupScanner] Sample sensitive paths:', dict.sensitive.slice(0, 5));

            // 合并所有路径并排序（优先级：VCS > 敏感文件 > 根目录备份 > 子目录备份）
            const allPaths = [
                ...dict.vcs.map(p => ({ path: p, type: 'vcs', priority: 1 })),
                ...dict.sensitive.map(p => ({ path: p, type: 'sensitive', priority: 2 })),
                ...dict.root.map(p => ({ path: p, type: 'backup', priority: 3 })),
                ...dict.subdirs.map(p => ({ path: p, type: 'backup', priority: 4 })),
            ];

            // 过滤已扫描的路径（带 TTL 检查）
            const toScan = [];
            const skippedByCache = [];
            for (const item of allPaths) {
                const key = `${hostname}|${item.path}`;

                if (hostScanned.has(key)) {
                    const ts = this.scannedTimestamps.get(key);
                    if (ts && Date.now() - ts <= this.scanTTL) {
                        skippedByCache.push(item.path);
                        continue; // 未过期，跳过
                    } else {
                        // 已过期，删除并重新扫描
                        hostScanned.delete(key);
                        this.scannedTimestamps.delete(key);
                    }
                }

                toScan.push(item);
            }

            console.log(`[BackupScanner] Total paths: ${allPaths.length}, Skipped by cache: ${skippedByCache.length}, To scan: ${toScan.length}`);
            if (skippedByCache.length > 0) {
                console.log('[BackupScanner] Skipped paths (first 10):', skippedByCache.slice(0, 10));
            }

            if (toScan.length === 0) {
                console.log('[BackupScanner] No new paths to scan');

                // 恢复历史发现记录
                const historyFindings = this.findingsHistory.get(hostname) || [];
                if (historyFindings.length > 0) {
                    console.log(`[BackupScanner] Restoring ${historyFindings.length} historical findings`);
                    this.findings.set(tabId, historyFindings);

                    // 通知 popup 显示历史记录
                    chrome.runtime.sendMessage({
                        action: 'BACKUP_FINDINGS',
                        tabId,
                        findings: historyFindings,
                    }).catch(() => {});
                }

                this.updateStatus(tabId, 'completed', 0, 0);
                return;
            }

            // 按优先级排序
            toScan.sort((a, b) => a.priority - b.priority);

            // 限制扫描数量（避免过多请求）
            const maxPaths = 200;
            const pathsToScan = toScan.slice(0, maxPaths);

            console.log(`[BackupScanner] Scanning ${pathsToScan.length} paths for ${hostname}`);
            console.log('[BackupScanner] First 20 paths to scan:', pathsToScan.slice(0, 20).map(p => p.path));
            this.updateStatus(tabId, 'scanning', 0, pathsToScan.length);

            // 并发扫描（带限流）
            await this.scanPaths(origin, pathsToScan, hostname, tabId);

            // 扫描完成
            this.updateStatus(tabId, 'completed', pathsToScan.length, pathsToScan.length);

        } catch (e) {
            console.error('[BackupScanner] Error:', e);
            this.updateStatus(tabId, 'error', 0, 0);
        }
    }

    /**
     * 并发扫描路径（带限流）
     */
    async scanPaths(origin, items, hostname, tabId) {
        const results = [];
        const hostScanned = this.scannedPaths.get(hostname);

        // 分批处理
        for (let i = 0; i < items.length; i += this.maxConcurrent) {
            const batch = items.slice(i, i + this.maxConcurrent);

            const promises = batch.map(item =>
                this.checkPath(origin, item.path, item.type)
                    .then(result => {
                        const key = `${hostname}|${item.path}`;
                        hostScanned.add(key);
                        this.scannedTimestamps.set(key, Date.now());
                        return result;
                    })
            );

            const batchResults = await Promise.allSettled(promises);

            for (const r of batchResults) {
                if (r.status === 'fulfilled' && r.value) {
                    results.push(r.value);
                }
            }

            // 更新进度
            const scanned = Math.min(i + this.maxConcurrent, items.length);
            this.updateStatus(tabId, 'scanning', scanned, items.length);

            // 实时通知发现（不等 AI 过滤）
            if (results.length > 0) {
                this.notifyFindings(results, tabId, hostname, false);
            }

            // 延迟（避免过快）
            if (i + this.maxConcurrent < items.length) {
                await new Promise(resolve => setTimeout(resolve, this.requestDelay));
            }
        }

        // AI 降噪（如果启用）- 在后台异步执行
        if (results.length > 0) {
            this.aiFilter(results, tabId).then(finalResults => {
                // 用 AI 过滤后的结果替换之前的结果
                if (finalResults.length !== results.length) {
                    this.findings.set(tabId, finalResults);
                    this.notifyFindings(finalResults, tabId, hostname, true);
                }
            }).catch(e => {
                console.warn('[BackupScanner] AI filter failed:', e);
            });
        }
    }

    /**
     * 通知发现的文件
     */
    notifyFindings(findings, tabId, hostname, isFiltered) {
        if (findings.length === 0) return;

        // 保存发现到当前 tab
        if (!this.findings.has(tabId)) {
            this.findings.set(tabId, []);
        }
        this.findings.set(tabId, findings);

        // 保存到历史记录（按 hostname）
        this.findingsHistory.set(hostname, findings);

        // 通知 popup
        chrome.runtime.sendMessage({
            action: 'BACKUP_FINDINGS',
            tabId,
            findings,
        }).catch(() => {});

        // 日志
        for (const finding of findings) {
            addLog('备份文件扫描', finding.url, 'backup', `发现: ${finding.type} - ${finding.size} bytes`);
        }

        // 通知（只在最终结果时显示）
        if (isFiltered) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon128.png'),
                title: `发现 ${findings.length} 个敏感文件`,
                message: `在 ${hostname} 发现备份文件或敏感信息泄露`,
            }).catch(() => {});
        }
    }

    /**
     * AI 降噪过滤
     */
    async aiFilter(findings, tabId) {
        try {
            // 获取 AI 设置
            const data = await chrome.storage.local.get(['settings']);
            const settings = data.settings || {};

            // 如果没有配置 AI，跳过过滤
            if (!settings.aiKey || !settings.aiProvider) {
                console.log('[BackupScanner] AI not configured, skipping filter');
                return findings;
            }

            // 准备 AI 输入（只发送前 2KB 内容片段）
            const payload = findings.map(f => ({
                url: f.url,
                path: f.path,
                type: f.type,
                status: f.status,
                size: f.size,
                contentType: f.contentType,
                contentPreview: f.contentPreview || '', // 内容预览
            }));

            // 调用 AI
            const { callAI } = await import('./index.js');
            const result = await callAI(
                settings.aiKey,
                settings.aiProvider,
                settings.aiModel,
                settings.aiEndpoint,
                { findings: payload },
                'backup_filter'
            );

            // AI 返回格式：{ valid: [url1, url2, ...], reason: { url: "原因" } }
            if (result?.valid && Array.isArray(result.valid)) {
                const validUrls = new Set(result.valid);
                const filtered = findings.filter(f => validUrls.has(f.url));

                console.log(`[BackupScanner] AI filtered: ${findings.length} -> ${filtered.length}`);
                return filtered;
            }

            // AI 调用失败，返回原始结果
            return findings;
        } catch (e) {
            console.warn('[BackupScanner] AI filter failed:', e);
            return findings;
        }
    }

    /**
     * 检查单个路径
     */
    async checkPath(origin, path, type) {
        const url = origin + path;

        try {
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'omit',
                redirect: 'manual',
                signal: AbortSignal.timeout(5000),
            });

            // 只接受 200 状态码
            if (response.status !== 200) {
                return null;
            }

            const contentLength = response.headers.get('content-length');
            const contentType = response.headers.get('content-type') || '';

            console.log(`[BackupScanner] Checking ${path}, type: ${type}, contentType: ${contentType}`);

            // 对于二进制文件（压缩包），使用 arrayBuffer
            let content;
            let isText = true;
            if (contentType.includes('zip') || contentType.includes('rar') ||
                contentType.includes('gzip') || contentType.includes('tar') ||
                contentType.includes('7z') || contentType.includes('octet-stream')) {
                const buffer = await response.arrayBuffer();
                content = new Uint8Array(buffer);
                isText = false;
                console.log(`[BackupScanner] Binary file detected: ${path}, size: ${content.byteLength}, first bytes: ${Array.from(content.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
            } else {
                content = await response.text();
                console.log(`[BackupScanner] Text file detected: ${path}, size: ${content.length}, preview: ${content.slice(0, 100)}`);
            }

            // 严格的内容验证
            const isValid = this.isValidContent(content, type, contentType, path, isText);
            console.log(`[BackupScanner] Validation result for ${path}: ${isValid}`);

            if (!isValid) {
                return null;
            }

            // 保存内容预览（前 2KB）供 AI 分析
            let contentPreview;
            if (isText) {
                contentPreview = content.slice(0, 2000);
            } else {
                // 对于二进制文件，提供文件头信息供 AI 识别
                const header = Array.from(content.slice(0, 16))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                contentPreview = `[Binary file, header: ${header}]`;
            }

            return {
                url,
                path,
                type,
                status: response.status,
                size: contentLength ? parseInt(contentLength) : (isText ? content.length : content.byteLength),
                contentType: contentType || 'unknown',
                contentPreview,
                foundAt: Date.now(),
            };
        } catch (e) {
            console.warn(`[BackupScanner] Error checking ${path}:`, e.message);
            // 超时或网络错误，跳过
            return null;
        }
    }

    /**
     * 验证内容是否为真实的敏感文件（严格过滤误报）
     */
    isValidContent(content, type, contentType, path, isText = true) {
        if (!content || (isText && content.length === 0) || (!isText && content.byteLength === 0)) {
            return false;
        }

        // 对于二进制内容，直接进行二进制验证
        if (!isText) {
            return this.isValidBackup(content, path, contentType, false);
        }

        const text = content;

        // 1. 通用误报特征（404/错误页面）
        const errorPatterns = [
            /404|not found|file not found|page not found/i,
            /error page|error occurred|unexpected error/i,
            /whitelabel error page/i,
            /no mapping for|no static resource/i,
            /access denied|forbidden|unauthorized/i,
            /nginx.*error|apache.*error/i,
        ];

        for (const pattern of errorPatterns) {
            if (pattern.test(text)) {
                return false;
            }
        }

        // 2. 检查是否为 HTML 错误页面（长度 < 5KB 且包含 HTML 标签）
        if (text.length < 5000 && /<html|<body|<head/i.test(text)) {
            // 如果是 HTML，必须不包含错误关键词
            if (/error|404|not found|exception/i.test(text)) {
                return false;
            }
        }

        // 3. 类型特定验证
        if (type === 'vcs') {
            return this.isValidVCS(text, path);
        } else if (type === 'sensitive') {
            return this.isValidSensitive(text, path, contentType);
        } else if (type === 'backup') {
            return this.isValidBackup(text, path, contentType, true);
        }

        return true;
    }

    /**
     * 验证版本控制文件
     */
    isValidVCS(text, path) {
        // SVN entries
        if (path.includes('.svn/entries')) {
            return text.includes('svn:') || /^\d+\n/.test(text);
        }

        // SVN wc.db (SQLite database)
        if (path.includes('.svn/wc.db')) {
            return text.startsWith('SQLite format');
        }

        // Mercurial
        if (path.includes('.hg/requires')) {
            return /revlogv1|store|fncache/i.test(text);
        }

        // CVS
        if (path.includes('CVS/Entries')) {
            return text.includes('/') && /^\/.*\/\d/.test(text);
        }

        return false;
    }

    /**
     * 验证敏感文件
     */
    isValidSensitive(text, path, contentType) {
        // .env 文件
        if (path.endsWith('.env') || path.includes('.env.')) {
            // 必须包含环境变量格式
            return /^[A-Z_]+=/m.test(text) || /^export [A-Z_]+=/m.test(text);
        }

        // PHP 配置文件
        if (path.endsWith('.php')) {
            // 必须包含 PHP 代码
            return text.includes('<?php') || text.includes('<?=');
        }

        // JSON 配置文件
        if (path.endsWith('.json')) {
            try {
                JSON.parse(text);
                return true;
            } catch {
                return false;
            }
        }

        // YAML 配置文件
        if (path.endsWith('.yml') || path.endsWith('.yaml')) {
            return /^[a-z_]+:\s*.+/im.test(text);
        }

        // SQL 文件
        if (path.endsWith('.sql')) {
            return /CREATE TABLE|INSERT INTO|SELECT \* FROM|DROP TABLE/i.test(text);
        }

        // 日志文件
        if (path.includes('.log') || path.includes('_log')) {
            // 必须包含日志格式（时间戳、级别等）
            return /\d{4}-\d{2}-\d{2}|\[ERROR\]|\[INFO\]|\[WARN\]/i.test(text);
        }

        // Docker 文件
        if (path.includes('Dockerfile') || path.includes('docker-compose')) {
            return /FROM |RUN |COPY |CMD |ENTRYPOINT |version:|services:/i.test(text);
        }

        return true; // 其他敏感文件，保守通过
    }

    /**
     * 验证备份文件
     */
    isValidBackup(content, path, contentType, isText = true) {
        // 如果是二进制数据（Uint8Array）
        if (!isText && content instanceof Uint8Array) {
            // ZIP 文件头: PK\x03\x04 或 PK\x05\x06
            if (content.length >= 4 && content[0] === 0x50 && content[1] === 0x4B &&
                (content[2] === 0x03 || content[2] === 0x05)) {
                return true;
            }

            // RAR 文件头: Rar!
            if (content.length >= 4 && content[0] === 0x52 && content[1] === 0x61 &&
                content[2] === 0x72 && content[3] === 0x21) {
                return true;
            }

            // GZIP 文件头: 0x1f 0x8b
            if (content.length >= 2 && content[0] === 0x1f && content[1] === 0x8b) {
                return true;
            }

            // 7z 文件头: 7z\xBC\xAF\x27\x1C
            if (content.length >= 6 && content[0] === 0x37 && content[1] === 0x7A &&
                content[2] === 0xBC && content[3] === 0xAF && content[4] === 0x27 && content[5] === 0x1C) {
                return true;
            }

            return false;
        }

        // 文本内容验证
        const text = content;

        // 压缩文件特征（二进制文件头）
        const zipMagic = text.charCodeAt(0) === 0x50 && text.charCodeAt(1) === 0x4B &&
                         (text.charCodeAt(2) === 0x03 || text.charCodeAt(2) === 0x05);
        const rarMagic = text.charCodeAt(0) === 0x52 && text.charCodeAt(1) === 0x61 &&
                         text.charCodeAt(2) === 0x72 && text.charCodeAt(3) === 0x21;
        const gzipMagic = text.charCodeAt(0) === 0x1f && text.charCodeAt(1) === 0x8b;
        const tarMagic = text.includes('ustar');
        const sevenZipMagic = text.charCodeAt(0) === 0x37 && text.charCodeAt(1) === 0x7A &&
                              text.charCodeAt(2) === 0xBC;

        if (zipMagic || rarMagic || gzipMagic || tarMagic || sevenZipMagic) {
            return true;
        }

        // SQL 备份文件
        if (path.endsWith('.sql') || path.includes('.sql.')) {
            return /CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE|SELECT \*/i.test(text);
        }

        // WAR/JAR 文件（实际上是 ZIP 格式）
        if (path.endsWith('.war') || path.endsWith('.jar')) {
            return zipMagic || text.includes('META-INF') || text.includes('WEB-INF');
        }

        // .bak/.old/.tmp 等备份后缀
        if (/\.(bak|old|tmp|backup|save|orig)$/i.test(path)) {
            // 必须不是错误页面
            return text.length > 100 && !/error|404|not found/i.test(text);
        }

        return false;
    }

    /**
     * 获取发现结果
     */
    getFindings(tabId) {
        return this.findings.get(tabId) || [];
    }

    /**
     * 清理过期扫描记录
     */
    cleanupExpired() {
        const now = Date.now();
        const expiredKeys = [];

        for (const [key, ts] of this.scannedTimestamps.entries()) {
            if (now - ts > this.scanTTL) {
                expiredKeys.push(key);
            }
        }

        for (const key of expiredKeys) {
            this.scannedTimestamps.delete(key);
            const [hostname, path] = key.split('|');
            const hostSet = this.scannedPaths.get(hostname);
            if (hostSet) {
                hostSet.delete(key);
            }
        }

        if (expiredKeys.length > 0) {
            console.log(`[BackupScanner] Cleaned up ${expiredKeys.length} expired records`);
        }
    }

    /**
     * 重置 tab 数据
     */
    reset(tabId) {
        this.findings.delete(tabId);
        this.scanStatus.delete(tabId);
    }

    /**
     * 清除所有扫描缓存（用于调试）
     */
    clearCache() {
        this.scannedPaths.clear();
        this.scannedTimestamps.clear();
        this.findingsHistory.clear();
        console.log('[BackupScanner] Cache cleared');
    }
}

export const backupScanner = new BackupScanner();

// 暴露到全局用于调试
if (typeof globalThis !== 'undefined') {
    globalThis.backupScanner = backupScanner;
}

// 定期清理过期记录
setInterval(() => {
    backupScanner.cleanupExpired();
}, 5 * 60 * 1000); // 每 5 分钟

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.settings) {
        backupScanner.loadSettings();
    }
});
