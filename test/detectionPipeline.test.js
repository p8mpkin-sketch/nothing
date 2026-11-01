import { describe, it, expect } from 'vitest'
import { runPipeline } from '../src/background/detectionPipeline.js'

const URL = 'https://target.test/page'

describe('runPipeline — 守卫', () => {
  it('缺参返回空', async () => {
    expect((await runPipeline(null, URL, {})).vulnerabilities).toEqual([])
    expect((await runPipeline({}, null, {})).vulnerabilities).toEqual([])
  })

  it('无参数或无 snippet 返回空', async () => {
    expect((await runPipeline({ pageParamSample: [], inlineScriptSnippet: ['x'] }, URL, {})).vulnerabilities).toEqual([])
    expect((await runPipeline({ pageParamSample: ['PARAM: q=abc'], inlineScriptSnippet: [] }, URL, {})).vulnerabilities).toEqual([])
  })

  it('参数值不反射到任何 snippet → 无漏洞', async () => {
    const scanData = {
      pageParamSample: ['PARAM: q=markerABC'],
      inlineScriptSnippet: ['INLINE_SCRIPT_SNIPPET var x = 1;'],
    }
    expect((await runPipeline(scanData, URL, {})).vulnerabilities).toEqual([])
  })
})

describe('runPipeline — 端到端误报治理', () => {
  it('实体编码的反射不产出漏洞', async () => {
    const scanData = {
      pageParamSample: ['PARAM: q=markerABC'],
      htmlReflectionSnippet: ['HTML_REFLECTION (param: q): <div>&lt;b&gt;markerABC&lt;/b&gt;</div>'],
    }
    expect((await runPipeline(scanData, URL, {})).vulnerabilities).toEqual([])
  })
})

describe('runPipeline — DOM XSS 变量 taint(⑧)', () => {
  const NOVERIFY = { pocVerify: false }

  it('远距离变量流(source→变量→>200字符后 sink)现在能检出', async () => {
    const gap = ';'.padEnd(260, 'z') + ';'
    const scanData = {
      pageParamSample: ['PARAM: q=NOREFLECTVAL'],
      inlineScriptSinkSnippet: [
        `INLINE_SCRIPT_SINK_SNIPPET: var u = new URLSearchParams(location.search).get('q')${gap} el.innerHTML = u;`,
      ],
    }
    const res = await runPipeline(scanData, URL, NOVERIFY)
    const dom = res.vulnerabilities.find(v => v.type === 'DOM XSS')
    expect(dom).toBeTruthy()
    expect(dom.confidence).toBe(0.8) // taint 确认 → 更高置信度
  })

  it('邻近 source/sink(无变量链接)仍检出(不回归旧判据)', async () => {
    const scanData = {
      pageParamSample: ['PARAM: msg=NOREFLECTVAL'],
      inlineScriptSinkSnippet: [
        `INLINE_SCRIPT_SINK_SNIPPET: if(location.hash){ } el.innerHTML = renderTemplate();`,
      ],
    }
    const res = await runPipeline(scanData, URL, NOVERIFY)
    const dom = res.vulnerabilities.find(v => v.type === 'DOM XSS')
    expect(dom).toBeTruthy()
    expect(dom.confidence).toBe(0.75) // 邻近兜底
  })

  it('远距离且无变量链接 → 不报(避免碰巧同段的误报)', async () => {
    const gap = ';'.padEnd(300, 'x') + ';'
    const scanData = {
      pageParamSample: ['PARAM: q=NOREFLECTVAL'],
      inlineScriptSinkSnippet: [
        `INLINE_SCRIPT_SINK_SNIPPET: if(location.hash){log()}${gap} el.innerHTML = template;`,
      ],
    }
    const res = await runPipeline(scanData, URL, NOVERIFY)
    expect(res.vulnerabilities.find(v => v.type === 'DOM XSS')).toBeFalsy()
  })
})

describe('runPipeline — 真实反射产出漏洞', () => {
  it('JS 双引号字符串反射 → 产出带 POC 的漏洞条目', async () => {
    const scanData = {
      pageParamSample: ['PARAM: q=markerABC'],
      inlineScriptSnippet: ['INLINE_SCRIPT_SNIPPET var greeting = "markerABC";'],
    }
    // pocVerify 默认关闭（settings 不含 pocVerify），不会真开标签页验证
    const res = await runPipeline(scanData, URL, {})
    expect(res.vulnerabilities.length).toBeGreaterThan(0)
    const v = res.vulnerabilities[0]
    expect(Array.isArray(v.pocs)).toBe(true)
    expect(v.pocs.length).toBeGreaterThan(0)
    expect(v.poc).toBe(v.pocs[0])
  })
})
