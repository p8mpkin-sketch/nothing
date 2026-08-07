/**
 * Shared rule-pattern matching used by ruleEngine, activeScanner, and networkMonitor.
 * Avoids the same logic duplicated in 3 places.
 */

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
    try {
      contentMatch = new RegExp(rule.pattern, 'i').test(content);
    } catch {
      // Invalid regex → no match
    }
  } else {
    const nc = (content || '').toLowerCase().replace(/\s+/g, ' ');
    const np = (rule.pattern || '').toLowerCase().replace(/\s+/g, ' ');
    contentMatch = nc.includes(np);
  }

  const isMatch = rule.matchStatusCode
    ? (rule.matchCondition === 'or' ? (statusMatch || contentMatch) : (statusMatch && contentMatch))
    : contentMatch;

  return { isMatch, statusMatch, contentMatch };
}
