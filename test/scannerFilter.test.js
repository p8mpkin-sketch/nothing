import { describe, it, expect, beforeAll } from 'vitest'

// scanner.filter.js 是内容脚本(plain IIFE),通过 window.SCANNER_FILTER 暴露,不是 ESM。
// 这里先搭 window stub 再 import 执行它,然后读 window.SCANNER_FILTER,
// 既能测到内容脚本逻辑,又不必给源文件加 export(保持 IIFE 注入形态不变)。
let F
beforeAll(async () => {
  globalThis.window = {}
  await import('../src/content/scanner.filter.js')
  F = globalThis.window.SCANNER_FILTER
})

describe('shannonEntropy', () => {
  it('全同字符熵为 0', () => {
    expect(F.shannonEntropy('aaaaaaaa')).toBe(0)
  })
  it('空串熵为 0', () => {
    expect(F.shannonEntropy('')).toBe(0)
  })
  it('两等概字符熵为 1', () => {
    expect(F.shannonEntropy('abababab')).toBeCloseTo(1, 5)
  })
  it('高多样性串熵更高', () => {
    expect(F.shannonEntropy('AKIAIOSFODNN7EXAMPLE')).toBeGreaterThan(3)
  })
})

describe('isRealSecret — 香农熵下限(误报治理语料)', () => {
  // 低熵垃圾:应判为"不是真密钥"
  const notSecret = [
    ['全同字符', 'aaaaaaaaaaaa'],
    ['两字符交替', 'abababababab'],
    ['纯重复数字', '121212121212'],
    ['全零', '000000000000'],
    ['重复符号', '------------'],
  ]
  it.each(notSecret)('%s → false', (_label, val) => {
    expect(F.isRealSecret(val)).toBe(false)
  })

  // 真密钥/高熵:熵下限不应误杀(仍返回 true)
  const realSecret = [
    // 注:不用真实密钥前缀(如 sk_live_),否则 GitHub 推送保护会拦夹具
    ['随机高熵令牌', 'Xq7Tz9Kp2Rm4Wb8Ln6Vc3Hd5Fg1Js0Ay'],
    ['混合十六进制', 'a1b2c3d4e5f6g7h8i9j0'],
    ['长随机串含符号', 'Zt4-Np9_Rk2xBv7Qm3Ld8'],
  ]
  it.each(realSecret)('%s → true', (_label, val) => {
    expect(F.isRealSecret(val)).toBe(true)
  })
})
