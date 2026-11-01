/**
 * Shared rule-pattern matching used by ruleEngine, activeScanner, and networkMonitor.
 * Avoids the same logic duplicated in 3 places.
 */

// ── 编译缓存 ────────────────────────────────────────────────────────────────────
// matchContent 过去每次调用都 `new RegExp(pattern, 'i')`，N 条规则 × M 个请求
// 全程重复编译。这里按 pattern 缓存编译结果(非法正则缓存为 null)，编译成本从
// O(规则×请求) 降到 O(唯一 pattern)。
const _regexCache = new Map();
const REGEX_CACHE_MAX = 1000;

function getCompiledRegex(pattern) {
  if (_regexCache.has(pattern)) return _regexCache.get(pattern);
  let re = null;
  try {
    re = new RegExp(pattern, 'i');
  } catch {
    re = null; // 非法正则 → 缓存 null，下次直接命中不再重试编译
  }
  if (_regexCache.size >= REGEX_CACHE_MAX) {
    // 简单清理:删最早插入的一条(Map 保持插入序)
    const firstKey = _regexCache.keys().next().value;
    _regexCache.delete(firstKey);
  }
  _regexCache.set(pattern, re);
  return re;
}

// ── 归一化内容 memo(单条) ──────────────────────────────────────────────────────
// keyword 匹配要把整个 content 做 toLowerCase + 空白折叠。ruleEngine.match() 对同一
// 份 content 循环所有规则，过去每条规则都重算一遍。单条 memo:同一 content 只算一次，
// 不同 content 到来时覆盖(循环内 content 恒定 → 全命中;内存不累积)。
let _lastContent = null;
let _lastNormalized = '';

function normalizeContent(content) {
  const c = content || '';
  if (c === _lastContent) return _lastNormalized;
  _lastContent = c;
  _lastNormalized = c.toLowerCase().replace(/\s+/g, ' ');
  return _lastNormalized;
}

/**
 * @param {object} rule - { matchType, pattern, matchStatusCode, matchCondition }
 * @param {string} content - The body/header string to match against
 * @param {number|string} [statusCode] - Optional HTTP status code
 * @returns {{ isMatch: boolean, statusMatch: boolean, contentMatch: boolean }}
 */
export function matchContent(rule, content, statusCode) {
  let statusMatch = true;
  if (rule.matchStatusCode) {
    const allowed = String(rule.matchStatusCode).split(',').map(c => c.trim());
    statusMatch = allowed.includes(String(statusCode));
  }

  let contentMatch = false;
  if (rule.pattern === '^$') {
    contentMatch = !content || content.length === 0;
  } else if (rule.matchType === 'regex') {
    const re = getCompiledRegex(rule.pattern);
    contentMatch = re ? re.test(content) : false; // 非法正则 → 不命中
  } else {
    const nc = normalizeContent(content);
    const np = (rule.pattern || '').toLowerCase().replace(/\s+/g, ' ');
    contentMatch = nc.includes(np);
  }

  const isMatch = rule.matchStatusCode
    ? (rule.matchCondition === 'or' ? (statusMatch || contentMatch) : (statusMatch && contentMatch))
    : contentMatch;

  return { isMatch, statusMatch, contentMatch };
}
