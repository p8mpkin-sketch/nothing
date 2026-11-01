import { describe, it, expect } from 'vitest'
import { getParentHierarchies } from '../src/background/urlParser.js'

describe('getParentHierarchies', () => {
  it('列出各级父目录，最深在前，含根', () => {
    const out = getParentHierarchies('https://example.com/a/b/c')
    expect(out).toEqual([
      'https://example.com/a/b/c/',
      'https://example.com/a/b/',
      'https://example.com/a/',
      'https://example.com/',
    ])
  })

  it('跳过静态资源目录与静态文件，只剩根', () => {
    const out = getParentHierarchies('https://example.com/assets/app.js')
    expect(out).toEqual(['https://example.com/'])
  })

  it('非 http(s) 协议返回空', () => {
    expect(getParentHierarchies('ftp://host/a/b')).toEqual([])
  })

  it('非法 URL 返回空', () => {
    expect(getParentHierarchies('not a url')).toEqual([])
  })

  it('根路径只返回根', () => {
    expect(getParentHierarchies('https://example.com/')).toEqual([
      'https://example.com/',
    ])
  })
})
