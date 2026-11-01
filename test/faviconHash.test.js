import { describe, it, expect } from 'vitest'
import { mmh3_x86_32, base64EncodeBytesFormat, fofaFaviconHash } from '../src/utils/faviconHash.js'

describe('mmh3_x86_32 — 公开测试向量(非循环校验)', () => {
  // 这些是 MurmurHash3 x86_32 的权威公开向量,确保实现与 fofa/Python mmh3 一致
  it('空串 seed=0 → 0', () => {
    expect(mmh3_x86_32('', 0)).toBe(0)
  })
  it('空串 seed=1 → 0x514e28b7', () => {
    expect(mmh3_x86_32('', 1) >>> 0).toBe(0x514e28b7)
  })
  it('空串 seed=0xffffffff → 0x81f16f39', () => {
    expect(mmh3_x86_32('', 0xffffffff) >>> 0).toBe(0x81f16f39)
  })
  it('"test" seed=0 → 0xba6bd213', () => {
    expect(mmh3_x86_32('test', 0) >>> 0).toBe(0xba6bd213)
  })
  it('"Hello, world!" seed=0 → 0xc0363e43', () => {
    expect(mmh3_x86_32('Hello, world!', 0) >>> 0).toBe(0xc0363e43)
  })
  it('接受 Uint8Array 与等价字符串结果一致', () => {
    expect(mmh3_x86_32(new TextEncoder().encode('test'), 0)).toBe(mmh3_x86_32('test', 0))
  })
})

describe('base64EncodeBytesFormat — 对齐 Python base64.encodebytes', () => {
  it('每 76 字符折行,含末行后都有 \\n', () => {
    const b64 = 'A'.repeat(200) // 200 = 76 + 76 + 48
    const out = base64EncodeBytesFormat(b64)
    const lines = out.split('\n')
    // 3 行内容 + 末尾 \n 产生的空串
    expect(lines).toHaveLength(4)
    expect(lines[0]).toHaveLength(76)
    expect(lines[1]).toHaveLength(76)
    expect(lines[2]).toHaveLength(48)
    expect(lines[3]).toBe('')
    expect(out.endsWith('\n')).toBe(true)
  })
  it('空串 → 仅一个换行', () => {
    expect(base64EncodeBytesFormat('')).toBe('\n')
  })
})

describe('fofaFaviconHash', () => {
  it('返回有符号 32 位,且与折行文本的 mmh3 自洽', () => {
    const b64 = 'AAECAwQFBgcICQoLDA0ODw==' // 任意 base64
    const got = fofaFaviconHash(b64)
    const raw = mmh3_x86_32(base64EncodeBytesFormat(b64), 0)
    const expected = raw > 0x7fffffff ? raw - 0x100000000 : raw
    expect(got).toBe(expected)
    // 在 32 位有符号范围内
    expect(got).toBeGreaterThanOrEqual(-0x80000000)
    expect(got).toBeLessThanOrEqual(0x7fffffff)
  })
})
