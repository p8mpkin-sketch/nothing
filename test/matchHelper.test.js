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

  // 编译缓存:同一 pattern 多次调用结果一致;非法正则缓存后仍稳定不命中不抛
  it('正则编译缓存:重复调用结果稳定', () => {
    const rule = { matchType: 'regex', pattern: 'ab+c' }
    expect(matchContent(rule, 'xabbbc').contentMatch).toBe(true)
    expect(matchContent(rule, 'nope').contentMatch).toBe(false)
    expect(matchContent(rule, 'abc').contentMatch).toBe(true)
  })

  it('非法正则缓存后多次调用都不命中且不抛', () => {
    const rule = { matchType: 'regex', pattern: '(unclosed' }
    expect(() => matchContent(rule, 'x')).not.toThrow()
    expect(matchContent(rule, 'x').contentMatch).toBe(false)
    expect(matchContent(rule, '(unclosed').contentMatch).toBe(false)
  })

  it('同内容不同规则的 keyword 归一结果一致(memo 不串味)', () => {
    const content = 'The Quick  Brown   FOX'
    expect(matchContent({ matchType: 'keyword', pattern: 'quick brown' }, content).contentMatch).toBe(true)
    expect(matchContent({ matchType: 'keyword', pattern: 'lazy dog' }, content).contentMatch).toBe(false)
    expect(matchContent({ matchType: 'keyword', pattern: 'fox' }, content).contentMatch).toBe(true)
  })
})
