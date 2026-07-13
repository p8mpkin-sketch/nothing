/**
 * detectionPipeline — XSS 检测流水线
 *
 * 统一编排检测流程，取代 index.js 中碎片化的 autoAnalyzeVulns/mergeVulnResults/
 * enrichReflectedXssPocs/buildReflectedXssPayloads 函数。
 *
 * 流程：
 *   Reflection Discovery (scanData → params + snippets)
 *     → Context Analysis (pocEngine.parseReflectionContext)
 *     → POC Generation (pocEngine.generatePocs)
 *     → Confidence Scoring
 *     → POC Verification (pocVerifier.verifyXssFindings)
 *     → Result Output
 *
 * 支持两条发现路径：
 *   - 静态路径：从 scanData 的 snippet 中直接匹配参数反射
 *   - AI 路径：AI 分析 JS 代码后输出的漏洞候选 + POC
 *   两者都使用 pocEngine 做 POC 生成，确保一致性。
 */

import { parseReflectionContext, generatePocs, extractParamNames, extractParamValue, wafStrategy, CTX, ENC } from './pocEngine';
import { verifyXssFindings } from './pocVerifier';

// ── 入口 ────────────────────────────────────────────────────────────────────────

/**
 * 运行完整检测流水线。
 *
 * @param {Object} scanData - 从 content script 收集的扫描数据
 * @param {string} pageUrl - 当前页面 URL
 * @param {Object} settings - 用户设置
 * @param {Function} [aiCall] - 可选的 AI 调用函数 (scanData) => vulnResult
 * @returns {Promise<Object>} { vulnerabilities, summary }
 */
export async function runPipeline(scanData, pageUrl, settings, aiCall = null) {
  const startTime = Date.now();
  const result = { vulnerabilities: [], summary: '' };

  if (!scanData || !pageUrl) return result;

  const pageParams = scanData.pageParamSample || [];
  const snippets = [
    ...(scanData.inlineScriptSnippet || []),
    ...(scanData.inlineScriptSinkSnippet || []),
    ...(scanData.inlineScriptProbeSnippet || []),
    ...(scanData.htmlReflectionSnippet || []),
  ];

  if (pageParams.length === 0 || snippets.length === 0) return result;

  // ── Phase 1: 反射发现 ──────────────────────────────────────────────────────
  //
  // 从 pageParams 和 snippets 中找出所有"参数值出现在 snippet 中"的反射配对。

  const paramNames = extractParamNames(pageParams);
  if (paramNames.length === 0) return result;

  const reflections = [];
  for (const paramName of paramNames) {
    const paramValue = extractParamValue(pageParams, paramName);
    if (!paramValue || paramValue.length < 2) continue;

    for (const snippet of snippets) {
      if (!snippet.includes(paramValue)) continue;
      reflections.push({ paramName, paramValue, snippet });
    }
  }

  if (reflections.length === 0) {
    // Phase 1b: 无反射匹配时，检查 sink snippet 中的 DOM source→sink 链
    // 这是 DOM XSS 的主要发现路径（参数值不在 snippet 中，但 JS 里有 source/sink）
    const domXssResults = detectDomXssFromSinks(scanData, pageUrl, paramNames);
    if (domXssResults.vulnerabilities.length > 0) {
      domXssResults.analyzedAt = Date.now();
      domXssResults.pipelineTime = Date.now() - startTime;
      return domXssResults;
    }
    return result;
  }

  // ── Phase 2: 上下文分析 ────────────────────────────────────────────────────
  //
  // 每个反射点 → pocEngine 分析上下文 → 判断可利用性

  const analyzed = [];
  for (const ref of reflections) {
    const context = parseReflectionContext(ref.snippet, ref.paramValue);
    if (!context) continue;

    analyzed.push({
      ...ref,
      context,
      exploitability: context.exploitability,
      confidence: context.exploitability,
    });
  }

  if (analyzed.length === 0) return result;

  // ── Phase 3: 按可利用性排序 + 去重 ─────────────────────────────────────────

  // 去重：同一 (paramName + contextType) 只保留最高 exploitability 的一条
  const bestByRef = new Map();
  for (const a of analyzed) {
    const key = `${a.paramName}|${a.context.contextType}`;
    const prev = bestByRef.get(key);
    if (!prev || a.exploitability > prev.exploitability) {
      bestByRef.set(key, a);
    }
  }

  const candidates = [...bestByRef.values()]
    .filter(a => a.exploitability >= 0.3) // 太低的不值得生成 POC
    .sort((a, b) => b.exploitability - a.exploitability);

  if (candidates.length === 0) return result;

  // ── Phase 4: POC 生成 ──────────────────────────────────────────────────────

  for (const cand of candidates) {
    const pocs = generatePocs(cand.context, pageUrl, cand.paramName);
    if (pocs.length === 0) continue;

    const vuln = buildVulnEntry(cand, pocs);
    result.vulnerabilities.push(vuln);
  }

  // ── Phase 5: POC 验证（可选，由设置控制） ─────────────────────────────────
  //
  // 返回三态：
  //   verified        → 弹窗了 ✓ 保持 HIGH
  //   wafBlocked      → 被 WAF 拦 🛡️ 保持 HIGH + 标记
  //   falsePositive   → 误报 ✂️ 从结果中移除

  if (settings?.pocVerify !== false && result.vulnerabilities.length > 0) {
    const { verifiedCount, wafBlockedVulns, falsePositives } = await verifyXssFindings(result.vulnerabilities);

    // 误报 → 从结果中彻底移除
    if (falsePositives.length > 0) {
      const fpSet = new Set(falsePositives);
      result.vulnerabilities = result.vulnerabilities.filter(v => !fpSet.has(v));
    }

    // WAF 拦截 → 标记，保持 HIGH
    for (const v of wafBlockedVulns) {
      v.verdict = 'waf_blocked';
      v.severity = 'high';
      v.confidence = Math.min(v.confidence || 0.7, 0.7);
      v.analysis = (v.analysis || '') + '\n\n🛡️ POC 均被 WAF 拦截（检测到 WAF 阻断页特征）。绕过策略不足以突破当前 WAF，可开启 AI 绕过尝试。';
    }

    // 验证成功 → 反馈给 WAF 策略管理器
    for (const v of result.vulnerabilities) {
      if (v.verified) {
        for (const p of v.pocs || []) {
          const matched = v._pocMeta?.find(m => m.url === p);
          if (matched) wafStrategy.recordSuccess(matched.strategy);
        }
      }
    }
  }

  // ── 生成摘要 ────────────────────────────────────────────────────────────────
  const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length;
  const total = result.vulnerabilities.length;
  const domCount = result.vulnerabilities.filter(v => v.type === 'DOM XSS').length;
  if (total > 0) {
    if (domCount > 0 && domCount === total) {
      result.summary = `发现 ${total} 个 DOM XSS 漏洞`;
    } else {
      result.summary = `发现 ${total} 个 XSS 漏洞`;
    }
    if (highCount > 0) result.summary += `，其中 ${highCount} 个高危`;
    const verifiedCount = result.vulnerabilities.filter(v => v.verified).length;
    if (verifiedCount > 0) result.summary += `（${verifiedCount} 个已实测弹窗）`;
  }

  result.analyzedAt = Date.now();
  result.pipelineTime = Date.now() - startTime;
  return result;
}

// ── 构建统一漏洞条目 ────────────────────────────────────────────────────────────

/**
 * 将上下文分析结果 + POC 列表转为标准漏洞条目。
 * 格式与现有系统兼容（popup/UI 不感知底层变化）。
 */
function buildVulnEntry(cand, pocs) {
  const { paramName, context } = cand;

  // 类型标题
  const typeLabels = {
    [CTX.JS_STRING_DQ]: 'Reflected XSS - JavaScript String Injection',
    [CTX.JS_STRING_SQ]: 'Reflected XSS - JavaScript String Injection',
    [CTX.JS_TEMPLATE]: 'Reflected XSS - Template Literal Injection',
    [CTX.JS_TEMPLATE_EXPR]: 'Reflected XSS - Template Expression Injection',
    [CTX.HTML_ATTR_START]: 'Reflected XSS - Attribute Injection',
    [CTX.HTML_ATTR_EVENT]: 'Reflected XSS - Event Handler Injection',
    [CTX.HTML_BODY]: 'Reflected XSS - HTML Tag Injection',
    [CTX.DOM_SINK_HTML]: 'DOM XSS',
    [CTX.DOM_SINK_EVAL]: 'DOM XSS - Code Execution',
  };

  // sink 描述
  const sinkLabels = {
    [CTX.JS_STRING_DQ]: 'JavaScript string literal (double-quoted)',
    [CTX.JS_STRING_SQ]: 'JavaScript string literal (single-quoted)',
    [CTX.JS_TEMPLATE]: 'Template literal',
    [CTX.JS_TEMPLATE_EXPR]: 'Template expression ${}',
    [CTX.HTML_ATTR_START]: `${context.attrName || 'href/src'} attribute`,
    [CTX.HTML_ATTR_EVENT]: 'Event handler',
    [CTX.HTML_BODY]: 'HTML body',
    [CTX.DOM_SINK_HTML]: context.foundSink || 'innerHTML',
    [CTX.DOM_SINK_EVAL]: context.foundSink || 'eval',
  };

  // 分析文案
  const analysisText = buildAnalysisText(cand);

  // 置信度：来自上下文分析
  let confidence = Math.min(Math.max(cand.exploitability, 0.3), 0.95);

  // POC URLs（去重，最多 5 条）
  const pocUrls = [...new Set(pocs.map(p => p.url))].slice(0, 5);
  // 记录 POC 元信息，供验证反馈使用
  const pocMeta = pocs.slice(0, 5);

  return {
    type: typeLabels[context.contextType] || 'Reflected XSS',
    severity: 'high',
    confidence,
    source: `URL parameter: ${paramName}`,
    sink: sinkLabels[context.contextType] || 'unknown',
    chain: `URL param "${paramName}" → ${sinkLabels[context.contextType] || 'unknown'}`,
    analysis: analysisText,
    poc: pocUrls[0] || '',
    pocs: pocUrls,
    detectionMethod: 'pipeline',
    // isVerified 等由 pocVerifier 填充
    verified: false,
    verifiedPocs: [],
    _pocMeta: pocMeta,
  };
}

/**
 * 生成分析文案
 */
function buildAnalysisText(cand) {
  const { paramName, context } = cand;
  const val = context.paramValue || '';
  const qLabel = context.quoteType === '"' ? '双引号' :
    context.quoteType === "'" ? '单引号' : '无引号';
  const ctxLabel = context.inObject ? '（位于 JS 对象字面量中）' : '';

  let text = '';
  const ct = context.contextType;

  if (ct === CTX.JS_STRING_DQ || ct === CTX.JS_STRING_SQ) {
    text = `参数 "${paramName}" 的值（${val}）被反射进内联 <script> 的 JavaScript 字符串字面量（${qLabel}）${ctxLabel}。`;

    if (context.valueIsWholeString) {
      text += '\n\n值独占整个字符串内容，是最可靠的注入点。';
    } else {
      text += `\n\n值距字符串闭合引号仅 ${context.charsAfter} 个字符，跳转后即可注入。`;
    }

    if (context.inObject) {
      text += '\n\n主 POC 使用 "}...,{// 先闭合对象再重开吞尾——对象上下文中若只闭合引号会导致脚本语法错误而静默不执行。';
    }

    text += '\n\n绕 WAF 手法：\\u0061lert（unicode 混淆关键字）+ tagged template a`1`（免括号调用），避开对 "alert"、"(" 的规则匹配。';

  } else if (ct === CTX.JS_TEMPLATE || ct === CTX.JS_TEMPLATE_EXPR) {
    text = `参数 "${paramName}" 的值被反射进 JavaScript 模板字面量中。`;
    text += '\n\n模板字面量中可以使用 ${} 插入任意表达式，不需要闭合引号。';

  } else if (ct === CTX.HTML_ATTR_START) {
    text = `参数 "${paramName}" 的值位于 ${context.attrName} 属性取值的开头，可控制协议头，注入 javascript: / data: 执行脚本。`;

  } else if (ct === CTX.HTML_ATTR_EVENT) {
    text = `参数 "${paramName}" 的值被反射进 HTML 事件处理器中，可直接执行 JavaScript。`;

  } else if (ct === CTX.HTML_BODY) {
    text = `参数 "${paramName}" 的值被反射到 HTML body 中，可注入任意 HTML 标签和 JavaScript 代码。`;

  } else if (ct === CTX.DOM_SINK_HTML || ct === CTX.DOM_SINK_EVAL) {
    text = `检测到 DOM 型 XSS：参数 "${paramName}" 通过 ${context.foundSource || '未知 source'} 获取后流向 ${context.foundSink || '未知 sink'}。`;
  }

  return text;
}

// ── DOM XSS 发现（不依赖反射值匹配） ──────────────────────────────────────────

/**
 * 从 INLINE_SCRIPT_SINK_SNIPPET 中检测 DOM XSS：
 * 当 JS 代码片段同时包含 DOM source（location.search/URLSearchParams 等）
 * 和危险 sink（innerHTML/eval 等）时，说明存在 DOM XSS 链路。
 *
 * 这是一种"零 token"的 DOM XSS 检测方式——不需要发 JS 给 AI。
 */
function detectDomXssFromSinks(scanData, pageUrl, paramNames) {
  const result = { vulnerabilities: [], summary: '' };
  const sinkSnippets = [
    ...(scanData.inlineScriptSinkSnippet || []),
    ...(scanData.inlineScriptSnippet || []),
  ];
  if (sinkSnippets.length === 0) return result;

  const sources = [
    /location\.search/i,
    /location\.hash/i,
    /location\.href/i,
    /URLSearchParams/i,
    /document\.referrer/i,
    /document\.cookie/i,
    /window\.name/i,
    /postMessage/i,
    /addEventListener\s*\(\s*['"]message['"]/i,
    /localStorage\./i,
    /sessionStorage\./i,
  ];

  const sinks = [
    /innerHTML/i,
    /outerHTML/i,
    /insertAdjacentHTML/i,
    /document\.write/i,
    /document\.writeln/i,
    /\beval\s*\(/i,
    /new\s+Function\s*\(/i,
    /setTimeout\s*\(\s*['"`]/i,
    /setInterval\s*\(\s*['"`]/i,
  ];

  const highRiskParams = ['message', 'msg', 'call', 'name', 'callback', 'url', 'redirect', 'next', 'return', 'q', 'query', 'search', 'keyword', 'data', 'content', 'html'];

  for (const snippet of sinkSnippets) {
    // 去掉前缀标签
    const body = snippet.replace(/^(INLINE_SCRIPT_SINK_SNIPPET|INLINE_SCRIPT_SNIPPET|INLINE_SCRIPT_PROBE_SNIPPET)\s*(\([^)]*\))?:\s*/, '');
    if (body.length < 20) continue;

    // 查找 source
    let foundSource = null;
    for (const sp of sources) {
      const m = body.match(sp);
      if (m) { foundSource = m[0]; break; }
    }
    if (!foundSource) continue;

    // 查找 sink
    let foundSink = null;
    for (const sk of sinks) {
      const m = body.match(sk);
      if (m) { foundSink = m[0]; break; }
    }
    if (!foundSink) continue;

    // 两个在同一条 snippet 里 → DOM XSS
    // 找出最可能相关的参数名
    let paramName = '';
    // 优先从 snippet 里提取：get('name'), get("name"), get(`name`)
    const getMatch = body.match(/\.get\(['"`]([^'"`]+)['"`]\)/i);
    if (getMatch) paramName = getMatch[1];
    else if (paramNames.length > 0) {
      // 从高风险的参数名中选
      const intersect = paramNames.filter(p => highRiskParams.includes(p.toLowerCase()));
      paramName = intersect[0] || paramNames[0];
    }

    if (!paramName) continue;

    // 判断 sink 类型
    const isHtmlSink = /innerHTML|outerHTML|insertAdjacentHTML|document\.write/i.test(foundSink);
    const isEvalSink = /\beval|new\s+Function|setTimeout|setInterval/i.test(foundSink);

    // 生成 POC
    let payloads = [];
    if (isHtmlSink) {
      payloads = [
        '<img src=x onerror="document.title=\'__NOTHING_POC__\';document.cookie=\'__NOTHING_POC=1\'">',
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(1)>',
      ];
    } else if (isEvalSink) {
      payloads = [
        "document.title='__NOTHING_POC__';document.cookie='__NOTHING_POC=1'",
        'alert(document.domain)',
        'confirm(1)',
      ];
    }

    const pocs = buildPocUrlsSimple(pageUrl, paramName, payloads);

    // 分析文案
    let analysis = `检测到 DOM 型 XSS：${foundSource} → ${foundSink}。`;
    analysis += `\n\n页面内联脚本中包含了 DOM source（${foundSource}）和危险 sink（${foundSink}），且攻击者可通过参数 "${paramName}" 控制输入。`;
    if (isHtmlSink) {
      analysis += '\n\n数据流：URL 参数 → JavaScript 变量 → innerHTML 写入 DOM，可注入任意 HTML/JavaScript。';
    } else if (isEvalSink) {
      analysis += '\n\n数据流：URL 参数 → JavaScript 变量 → eval/Function 执行，可直接执行任意代码。';
    }

    const vuln = {
      type: 'DOM XSS',
      severity: 'high',
      confidence: 0.75,
      source: `DOM source: ${foundSource}`,
      sink: isHtmlSink ? 'innerHTML' : 'eval',
      chain: `${foundSource} → ${isHtmlSink ? 'innerHTML' : 'eval/setTimeout'}`,
      analysis,
      poc: pocs[0] || '',
      pocs,
      detectionMethod: 'pipeline',
      verified: false,
      verifiedPocs: [],
    };

    result.vulnerabilities.push(vuln);
    // 每个 tab 最多报一条 DOM XSS（避免重复）
    break;
  }

  if (result.vulnerabilities.length > 0) {
    result.summary = '发现 DOM XSS 漏洞';
  }
  return result;
}

/** 简单版构建 POC URL */
function buildPocUrlsSimple(pageUrl, paramName, payloads) {
  const out = [];
  if (!pageUrl || !paramName || !payloads?.length) return out;
  try {
    for (const payload of payloads) {
      const u = new URL(pageUrl);
      u.searchParams.set(paramName, payload);
      out.push(u.toString());
    }
  } catch {}
  return out;
}
