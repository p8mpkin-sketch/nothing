import { describe, it, expect } from 'vitest'
import { ExploitabilityCalibrator } from '../src/background/pocEngine.js'

// 用全新实例,避免污染模块单例 exploitabilityCalibrator
function fresh() { return new ExploitabilityCalibrator() }

describe('ExploitabilityCalibrator', () => {
  it('样本不足(<8)时 calibrate 原样返回(严格 no-op)', () => {
    const c = fresh()
    for (let i = 0; i < 7; i++) c.recordResult('js_string_dq', true)
    expect(c.calibrate('js_string_dq', 0.65)).toBe(0.65)
  })

  it('无该上下文记录时原样返回', () => {
    expect(fresh().calibrate('html_body', 0.5)).toBe(0.5)
  })

  it('样本足够且实测率低 → 下调(但受 ±0.2 漂移上限约束)', () => {
    const c = fresh()
    // 10 个样本全不弹:rate=0 → blended=0.65*0.7+0*0.3=0.455(未触及 -0.2 下限 0.45)
    for (let i = 0; i < 10; i++) c.recordResult('js_string_dq', false)
    const out = c.calibrate('js_string_dq', 0.65)
    expect(out).toBeCloseTo(0.455, 5)
    expect(out).toBeGreaterThanOrEqual(0.65 - 0.2)
    expect(out).toBeLessThan(0.65)
  })

  it('样本足够且实测率高 → 上调,夹在 [0,1] 与漂移内', () => {
    const c = fresh()
    for (let i = 0; i < 10; i++) c.recordResult('js_string_dq', true) // rate=1
    const out = c.calibrate('js_string_dq', 0.65)
    // blended=0.65*0.7+1*0.3=0.755,在 +0.2 漂移内
    expect(out).toBeCloseTo(0.755, 5)
    expect(out).toBeLessThanOrEqual(0.65 + 0.2)
    expect(out).toBeLessThanOrEqual(1)
  })

  it('不同上下文互不影响', () => {
    const c = fresh()
    for (let i = 0; i < 10; i++) c.recordResult('js_string_dq', false)
    expect(c.calibrate('html_body', 0.65)).toBe(0.65) // 另一上下文无样本 → 不动
  })

  it('空 contextType 不记录', () => {
    const c = fresh()
    c.recordResult(null, true)
    c.recordResult(undefined, true)
    expect(c.serialize()).toEqual({})
  })

  it('serialize / deserialize 往返', () => {
    const c = fresh()
    for (let i = 0; i < 3; i++) c.recordResult('html_body', true)
    const snap = c.serialize()
    const c2 = fresh()
    c2.deserialize(snap)
    expect(c2.serialize()).toEqual({ html_body: { pop: 3, total: 3 } })
  })
})
