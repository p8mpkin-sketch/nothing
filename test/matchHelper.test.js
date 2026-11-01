import { describe, it, expect } from 'vitest'
import { matchContent } from '../src/background/matchHelper.js'

describe('matchContent', () => {
  it('regex 命中', () => {
    const r = matchContent({ matchType: 'regex', pattern: 'foo.*bar' }, 'xx foobar yy')
    expect(r.contentMatch).toBe(true)
    expect(r.isMatch).toBe(true)
  })

  it('非法 regex 视为不命中（不抛）', () => {
    const r = matchContent({ matchType: 'regex', pattern: '([' }, 'anything')
    expect(r.contentMatch).toBe(false)
    expect(r.isMatch).toBe(false)
  })

  it('keyword 大小写与空白归一后子串匹配', () => {
    const r = matchContent({ matchType: 'keyword', pattern: 'Hello World' }, 'say   HELLO    world!')
    expect(r.contentMatch).toBe(true)
  })

  it('pattern ^$ 只命中空内容', () => {
    expect(matchContent({ pattern: '^$' }, '').contentMatch).toBe(true)
    expect(matchContent({ pattern: '^$' }, 'x').contentMatch).toBe(false)
  })

  it('status + content 的 and 条件：两者都要满足', () => {
    const rule = { matchType: 'keyword', pattern: 'zzz', matchStatusCode: '200,302', matchCondition: 'and' }
    // 状态命中但内容不命中 → 整体不命中
    expect(matchContent(rule, 'no-match', 200).isMatch).toBe(false)
    // 状态命中且内容命中 → 命中
    expect(matchContent(rule, 'has zzz here', 200).isMatch).toBe(true)
    // 状态不命中 → 不命中
    expect(matchContent(rule, 'has zzz here', 404).isMatch).toBe(false)
  })

  it('status + content 的 or 条件：命中其一即可', () => {
    const rule = { matchType: 'keyword', pattern: 'zzz', matchStatusCode: '200', matchCondition: 'or' }
    expect(matchContent(rule, 'no-match', 200).isMatch).toBe(true) // 状态命中
    expect(matchContent(rule, 'has zzz', 500).isMatch).toBe(true)  // 内容命中
    expect(matchContent(rule, 'no-match', 500).isMatch).toBe(false)
  })
})
