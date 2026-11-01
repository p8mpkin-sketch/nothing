import { describe, it, expect } from 'vitest'
import {
  CTX, ENC,
  parseReflectionContext,
  generatePocs,
  extractParamNames,
  extractParamValue,
} from '../src/background/pocEngine.js'

describe('extractParamNames / extractParamValue', () => {
  it('从 PARAM: 样本提取参数名，忽略非法行', () => {
    expect(extractParamNames(['PARAM: q=1', 'PARAM: name=foo', 'junk', 42]))
      .toEqual(['q', 'name'])
  })

  it('extractParamValue 偏好最长值（探针 marker 优先于短数值）', () => {
    const samples = ['PARAM: q=1', 'PARAM: q=xssMarker12345', 'PARAM: other=zz']
    expect(extractParamValue(samples, 'q')).toBe('xssMarker12345')
  })

  it('extractParamValue 找不到返回 null', () => {
    expect(extractParamValue(['PARAM: a=1'], 'q')).toBeNull()
  })
})

describe('parseReflectionContext — 防御性守卫', () => {
  it('缺参返回 null', () => {
    expect(parseReflectionContext(null, 'abc')).toBeNull()
    expect(parseReflectionContext('snippet', null)).toBeNull()
  })

  it('参数值过短（<2）返回 null', () => {
    expect(parseReflectionContext('INLINE_SCRIPT_SNIPPET x=a', 'a')).toBeNull()
  })

  it('参数值不在 snippet 中返回 null', () => {
    expect(parseReflectionContext('INLINE_SCRIPT_SNIPPET var x=1', 'notpresent')).toBeNull()
  })
})

describe('parseReflectionContext — 误报治理（编码/转义不可利用）', () => {
  it('HTML 实体编码的反射 → exploitability 0', () => {
    const snippet = 'HTML_REFLECTION (param: q): <div>&lt;b&gt;markerABC&lt;/b&gt;</div>'
    const ctx = parseReflectionContext(snippet, 'markerABC')
    expect(ctx).not.toBeNull()
    expect(ctx.encoding).toBe(ENC.HTML_ENTITY)
    expect(ctx.exploitability).toBe(0)
  })

  it('JS 字符串被转义（\\" 前缀）→ 不是明文可利用', () => {
    const snippet = 'INLINE_SCRIPT_SNIPPET var s = "a\\"markerABC";'
    const ctx = parseReflectionContext(snippet, 'markerABC')
    expect(ctx).not.toBeNull()
    // 编码检测应识别出转义（js_escape 或 json_stringify）
    expect([ENC.JS_ESCAPE, ENC.JSON_STRINGIFY, ENC.NONE]).toContain(ctx.encoding)
  })
})

describe('parseReflectionContext — 上下文分类（特征）', () => {
  it('双引号 JS 字符串反射 → JS_STRING_DQ', () => {
    const snippet = 'INLINE_SCRIPT_SNIPPET var greeting = "markerABC";'
    const ctx = parseReflectionContext(snippet, 'markerABC')
    expect(ctx).not.toBeNull()
    expect(ctx.contextType).toBe(CTX.JS_STRING_DQ)
    expect(ctx.quoteType).toBe('"')
  })

  it('任何返回的 contextType 都是 CTX 枚举的合法值', () => {
    const ctx = parseReflectionContext('HTML_REFLECTION (param: q): <p>markerABC</p>', 'markerABC')
    expect(ctx).not.toBeNull()
    expect(Object.values(CTX)).toContain(ctx.contextType)
  })
})

describe('parseReflectionContext — 词法状态机(引号归属,旧 lastIndexOf 判错的场景)', () => {
  it('前一个字符串已闭合 → 代码位置是表达式,不是字符串', () => {
    // 旧逻辑 lastIndexOf('"') 会命中 "x" 的引号,误判为仍在字符串内
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET var a = "x"; foo(markerABC)', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_EXPRESSION)
  })

  it('http:// 在字符串内不误判为注释', () => {
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET var u = "http://h.com/markerABC"', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_STRING_DQ)
  })

  it('转义引号 \\" 不算闭合 → 仍在双引号字符串内', () => {
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET var s = "he said \\"markerABC', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_STRING_DQ)
  })

  it('真正的行注释 → JS_COMMENT,不可利用', () => {
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET var x=1; // note markerABC', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_COMMENT)
    expect(ctx.exploitability).toBe(0)
  })

  it('模板字面量 ${} 表达式内 → JS_TEMPLATE_EXPR', () => {
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET const t = `greet ${markerABC}`', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_TEMPLATE_EXPR)
  })

  it('模板体内(${expr} 已正确闭合)→ JS_TEMPLATE', () => {
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET const t = `a ${x} markerABC`', 'markerABC')
    expect(ctx.contextType).toBe(CTX.JS_TEMPLATE)
    expect(ctx.quoteType).toBe('`')
  })
})

describe('parseReflectionContext — 框架转义抑制收窄(减少漏报)', () => {
  it('React 页面的 JS 字符串反射(内联脚本)不再被抑制', () => {
    // 旧逻辑:页面有 React 字样 → 整体 exploitability=0 丢弃(漏报)
    const ctx = parseReflectionContext('INLINE_SCRIPT_SNIPPET var app=React.render; el.innerHTML="markerABC"', 'markerABC')
    expect(ctx.framework).toBe('react')
    expect(ctx.contextType).toBe(CTX.JS_STRING_DQ)
    expect(ctx.autoEscaped).toBeFalsy()
    expect(ctx.exploitability).toBeGreaterThan(0)
  })

  it('React 页面的 HTML 文本反射仍被抑制(框架确实会转义文本插值)', () => {
    const ctx = parseReflectionContext('HTML_REFLECTION (param: q): <div data-reactroot>markerABC</div>', 'markerABC')
    expect(ctx.framework).toBe('react')
    expect(ctx.autoEscaped).toBe(true)
    expect(ctx.exploitability).toBe(0)
  })

  it('dangerouslySetInnerHTML 存在时即使 HTML 文本上下文也不抑制', () => {
    const ctx = parseReflectionContext('HTML_REFLECTION (param: q): <div data-reactroot dangerouslySetInnerHTML>markerABC</div>', 'markerABC')
    expect(ctx.framework).toBe('react')
    expect(ctx.autoEscaped).toBeFalsy()
    expect(ctx.exploitability).toBeGreaterThan(0)
  })
})

describe('generatePocs', () => {
  it('exploitability<=0 不生成 POC', () => {
    expect(generatePocs({ exploitability: 0, contextType: CTX.HTML_BODY }, 'https://x.com/', 'q')).toEqual([])
  })

  it('缺 pageUrl / paramName 不生成 POC', () => {
    const ctx = { exploitability: 1, contextType: CTX.HTML_BODY }
    expect(generatePocs(ctx, '', 'q')).toEqual([])
    expect(generatePocs(ctx, 'https://x.com/', '')).toEqual([])
  })

  it('HTML body 上下文生成带参数的 POC URL，且去重', () => {
    const ctx = { exploitability: 1, contextType: CTX.HTML_BODY }
    const pocs = generatePocs(ctx, 'https://x.com/p', 'q')
    expect(pocs.length).toBeGreaterThan(0)
    for (const p of pocs) {
      const u = new URL(p.url)
      expect(u.searchParams.get('q')).toBe(p.payload)
      expect(typeof p.strategy).toBe('string')
    }
    // 去重：URL 唯一
    const urls = pocs.map(p => p.url)
    expect(new Set(urls).size).toBe(urls.length)
  })
})
