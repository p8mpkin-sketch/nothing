import { describe, it, expect } from 'vitest'
import { staticXssDetector } from '../src/background/staticXssDetector.js'

describe('staticXssDetector.analyze — 守卫与白名单', () => {
  it('缺参返回空结果', () => {
    expect(staticXssDetector.analyze(null, 'https://x.com/').vulnerabilities).toEqual([])
    expect(staticXssDetector.analyze({}, null).vulnerabilities).toEqual([])
  })

  it('白名单域名直接跳过（不出漏洞）', () => {
    const scanData = {
      pageParamSample: ['PARAM: q=<script>markerABC</script>'],
      inlineScriptSnippet: ['HTML_REFLECTION (param: q): <div><script>markerABC</script></div>'],
    }
    expect(staticXssDetector.analyze(scanData, 'https://github.com/x').vulnerabilities).toEqual([])
  })

  it('无参数 / 无 snippet 返回空', () => {
    expect(staticXssDetector.analyze({ pageParamSample: [] }, 'https://x.com/').vulnerabilities).toEqual([])
    expect(staticXssDetector.analyze({ pageParamSample: ['PARAM: q=abc'] }, 'https://x.com/').vulnerabilities).toEqual([])
  })
})

describe('staticXssDetector.isRealXssContext — 误报治理语料', () => {
  // 每修一个误报，往这里加一条 case，锁死"这类上下文不该报"
  const notXss = [
    ['HTML 实体编码', '<div>&lt;script&gt;markerABC&lt;/script&gt;</div>', 'markerABC'],
    ['在 input value 属性内', '<input type="text" value="markerABC">', 'markerABC'],
    ['在 HTML 注释内', '<!-- debug: markerABC -->', 'markerABC'],
    ['纯文本无危险 payload', '<div>markerABC</div>', 'markerABC'],
  ]
  it.each(notXss)('%s → 不算 XSS', (_label, context, value) => {
    expect(staticXssDetector.isRealXssContext(context, value)).toBe(false)
  })

  const isXss = [
    ['反射进 <script> 标签', '<script>var a = markerABC;</script>', 'markerABC'],
    ['参数值本身带标签', '<div>markerABC</div>', '<img src=x onerror=alert(1)>'],
  ]
  it.each(isXss)('%s → 算 XSS', (_label, context, value) => {
    expect(staticXssDetector.isRealXssContext(context, value)).toBe(true)
  })
})
