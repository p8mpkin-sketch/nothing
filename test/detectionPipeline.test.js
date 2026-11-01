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
