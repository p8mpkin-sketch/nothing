// Fingerprint importer.
//
// Converts CEL-expression fingerprint definitions (the YAML format used by tools
// like xray / afrog, e.g. shiro / xxl-job) into this extension's internal active
// probe rule format.
//
// Input example:
//   header_contains_with_cookie:
//     request:
//       method: GET
//       path: /
//       headers: { Cookie: rememberMe=true }
//     expression: response.raw_header.bcontains(b'=deleteMe') || response.raw_header.bcontains(b'shiro-cas')
//
// The engine only supports a single `pattern` (contains / regex) plus an optional
// status-code AND/OR. We map the CEL boolean expression to one regex using
// zero-width lookaheads: `&&` -> concatenated `(?=[\s\S]*X)`, `||` -> alternation.
import yaml from 'js-yaml';

// ── Regex helpers ──────────────────────────────────────────────────────────────
function regexEscape(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── CEL expression tokenizer ───────────────────────────────────────────────────
// Structural tokens: '(' ')' '&&' '||' '!'. Everything else is an "atom"
// (a single condition such as a `.contains(...)` call or a `status == 200`).
// Grouping parens are distinguished from function-call parens by tracking whether
// we currently expect an operand.
function skipString(expr, i) {
  const quote = expr[i];
  i++;
  while (i < expr.length) {
    if (expr[i] === '\\') { i += 2; continue; }
    if (expr[i] === quote) return i + 1;
    i++;
  }
  return i;
}

// Read a full primary/comparison expression starting at i, respecting nested
// function-call parens, brackets and string literals. Stops at a top-level
// `&&`, `||`, or an unmatched `)` (which belongs to an enclosing group).
function readPrimary(expr, i) {
  let depth = 0;
  const n = expr.length;
  while (i < n) {
    const c = expr[i];
    if (c === '"' || c === "'") { i = skipString(expr, i); continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--; i++; continue;
    }
    if (depth === 0 && (expr.startsWith('&&', i) || expr.startsWith('||', i))) break;
    i++;
  }
  return i;
}

function tokenize(expr) {
  const tokens = [];
  let i = 0;
  const n = expr.length;
  let expectOperand = true;
  while (i < n) {
    const c = expr[i];
    if (/\s/.test(c)) { i++; continue; }
    if (expectOperand) {
      if (c === '(') { tokens.push({ t: 'lp' }); i++; continue; }
      if (c === '!' && expr[i + 1] !== '=') { tokens.push({ t: 'not' }); i++; continue; }
      const start = i;
      i = readPrimary(expr, i);
      const text = expr.slice(start, i).trim();
      if (text) tokens.push({ t: 'atom', v: text });
      expectOperand = false;
      continue;
    }
    // after an operand: expect operator, group close, or end
    if (c === ')') { tokens.push({ t: 'rp' }); i++; continue; }
    if (expr.startsWith('&&', i)) { tokens.push({ t: 'op', v: '&&' }); i += 2; expectOperand = true; continue; }
    if (expr.startsWith('||', i)) { tokens.push({ t: 'op', v: '||' }); i += 2; expectOperand = true; continue; }
    i++; // skip anything unexpected defensively
  }
  return tokens;
}

// ── Recursive-descent parser (|| lowest, && next, ! / atom / group highest) ─────
function parseExpression(tokens) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseOr() {
    let node = parseAnd();
    while (peek() && peek().t === 'op' && peek().v === '||') {
      next();
      node = { or: [node, parseAnd()] };
    }
    return node;
  }
  function parseAnd() {
    let node = parseNot();
    while (peek() && peek().t === 'op' && peek().v === '&&') {
      next();
      node = { and: [node, parseNot()] };
    }
    return node;
  }
  function parseNot() {
    if (peek() && peek().t === 'not') { next(); return { not: parseNot() }; }
    return parsePrimary();
  }
  function parsePrimary() {
    const tok = peek();
    if (!tok) return { atom: '' };
    if (tok.t === 'lp') {
      next();
      const node = parseOr();
      if (peek() && peek().t === 'rp') next();
      return node;
    }
    if (tok.t === 'atom') { next(); return { atom: tok.v }; }
    next();
    return { atom: '' };
  }
  const ast = parseOr();
  return ast;
}

// ── Atom analysis ──────────────────────────────────────────────────────────────
// Extract the string literal(s) and the referenced scope from a single condition.
const CONTAIN_FNS = ['contains', 'bcontains', 'icontains', 'startsWith', 'endsWith',
  'bstartsWith', 'bendsWith', 'matches'];

function firstLiteral(argText) {
  const m = argText.match(/b?(['"])((?:\\.|(?!\1).)*)\1/);
  if (!m) return null;
  // Unescape common YAML/CEL escapes already handled by yaml; here just \\ and \"
  return m[2].replace(/\\(['"\\])/g, '$1');
}

function analyzeAtom(atomText) {
  const lower = atomText.toLowerCase();

  // Scope: header vs body reference
  let scope = null;
  if (/raw_header|\.header|headers/.test(lower)) scope = 'response_header';
  if (/body/.test(lower)) scope = 'body';

  // Status-code comparison: response.status == 200  /  status in [200,301]
  const statusEq = atomText.match(/status\s*(?:==|in)\s*\[?\s*(\d{3}(?:\s*,\s*\d{3})*)/i);
  if (statusEq && !CONTAIN_FNS.some(fn => lower.includes(fn.toLowerCase() + '('))) {
    return { kind: 'status', codes: statusEq[1].split(',').map(s => s.trim()) };
  }

  // Contains-style condition -> extract literal
  const fn = CONTAIN_FNS.find(f => new RegExp('\\.' + f + '\\s*\\(', 'i').test(atomText));
  const parenIdx = atomText.indexOf('(');
  const argText = parenIdx >= 0 ? atomText.slice(parenIdx + 1) : '';
  const lit = firstLiteral(argText);
  if (lit == null) return { kind: 'unknown', text: atomText };

  const isRegexLit = fn === 'matches';
  return { kind: 'match', scope, literal: lit, isRegex: isRegexLit };
}

// ── AST -> regex fragment (zero-width, composable) ──────────────────────────────
function translateExpression(exprRaw) {
  const warnings = [];
  const statusCodes = new Set();
  const scopes = new Set();
  let literalCount = 0;
  let singleLiteral = null;

  const ast = parseExpression(tokenize(exprRaw));

  // emit returns a regex fragment string (may be '' for status/no-op atoms)
  function emit(node, negated = false) {
    if (node.atom !== undefined) {
      const info = analyzeAtom(node.atom);
      if (info.kind === 'status') {
        info.codes.forEach(c => statusCodes.add(c));
        return ''; // handled separately via matchStatusCode
      }
      if (info.kind === 'unknown') {
        warnings.push(`无法识别的条件片段,已忽略: ${node.atom.slice(0, 60)}`);
        return '';
      }
      if (info.scope) scopes.add(info.scope);
      literalCount++;
      singleLiteral = info.literal;
      const body = info.isRegex ? info.literal : regexEscape(info.literal);
      return negated ? `(?![\\s\\S]*${body})` : `(?=[\\s\\S]*${body})`;
    }
    if (node.not) {
      if (node.not.atom !== undefined) return emit(node.not, !negated);
      warnings.push('暂不支持对复合表达式取非(!),已按正向处理');
      return emit(node.not, negated);
    }
    if (node.and) {
      const parts = node.and.map(n => emit(n, negated)).filter(Boolean);
      return parts.join('');
    }
    if (node.or) {
      const parts = node.or.map(n => emit(n, negated)).filter(Boolean);
      if (parts.length === 0) return '';
      if (parts.length === 1) return parts[0];
      return `(?:${parts.join('|')})`;
    }
    return '';
  }

  const frag = emit(ast);

  // Scope resolution
  let scope = 'body';
  if (scopes.size === 1) scope = [...scopes][0];
  else if (scopes.size > 1) { scope = 'body'; warnings.push('表达式同时引用了响应头和响应体,已统一按响应体匹配(可能需手动调整)'); }
  else if (statusCodes.size > 0 && literalCount === 0) scope = 'body';

  // Status code -> matchStatusCode (treated as AND with content)
  const matchStatusCode = [...statusCodes].join(', ');
  const matchCondition = 'and';
  if (statusCodes.size > 0) {
    // If status was combined via OR at the top the semantics differ; warn conservatively.
    if (ast.or) warnings.push('状态码与内容为 OR 关系,已按 AND 近似处理');
  }

  // Optimization: a single positive contains -> simple "contains" rule
  if (literalCount === 1 && frag === `(?=[\\s\\S]*${regexEscape(singleLiteral)})`) {
    return { scope, matchType: 'contains', pattern: singleLiteral, matchStatusCode, matchCondition, warnings };
  }

  const pattern = frag ? `^${frag}` : '(?:)';
  return { scope, matchType: 'regex', pattern, matchStatusCode, matchCondition, warnings };
}

// ── Request field helpers ───────────────────────────────────────────────────────
function normalizePath(p) {
  if (p == null) return '/';
  let s = String(p).replace(/\{\{\s*(baseurl|entry|hostname|rootpath)\s*\}\}/gi, '').trim();
  return s === '' ? '/' : s;
}

function headersToString(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return Object.entries(headers)
    .filter(([k, v]) => k && v != null)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

// ── Public API ──────────────────────────────────────────────────────────────────
// Parse one or many fingerprint definitions. Returns { rules, warnings, errors }.
// Rules are returned WITHOUT ids (the caller assigns unique ids).
export function parseFingerprints(text, { namePrefix = '' } = {}) {
  const warnings = [];
  const errors = [];
  const rules = [];

  let doc;
  try {
    doc = yaml.load(text);
  } catch (e) {
    return { rules, warnings, errors: ['YAML 解析失败: ' + e.message] };
  }
  if (!doc || typeof doc !== 'object') {
    return { rules, warnings, errors: ['未识别的指纹格式(应为 name: { request, expression } 结构)'] };
  }

  // Either a single unnamed def, or a map of name -> def.
  let entries;
  if (doc.request && doc.expression != null) entries = [[namePrefix || 'fingerprint', doc]];
  else entries = Object.entries(doc);

  for (const [key, def] of entries) {
    if (!def || typeof def !== 'object' || !def.request) continue;
    if (def.expression == null) { warnings.push(`"${key}" 缺少 expression,已跳过`); continue; }

    const req = def.request || {};
    const method = String(req.method || 'GET').toUpperCase();
    if (method !== 'GET') warnings.push(`"${key}" 使用 ${method} 方法,当前仅支持 GET 探测,将以 GET 发送`);

    const t = translateExpression(String(def.expression));
    t.warnings.forEach(w => warnings.push(`"${key}": ${w}`));

    const probePath = normalizePath(req.path);
    rules.push({
      name: namePrefix ? `${namePrefix}-${key}` : key,
      enabled: true,
      probePath,
      requestHeaders: headersToString(req.headers),
      matchScope: t.scope,
      matchStatusCode: t.matchStatusCode,
      matchCondition: t.matchCondition,
      matchType: t.matchType,
      pattern: t.pattern,
      scope: '',
      action: 'alert',
      // Whole-site fingerprint (root-path probe, e.g. Shiro) -> dedupe per host so a
      // site using the framework on every path only alerts once. Path-specific probes
      // stay per-path (nginx sub-path reverse proxies keep distinct matches).
      hostDedupe: probePath === '/',
    });
  }

  if (rules.length === 0 && errors.length === 0) {
    errors.push('未解析出有效指纹规则,请检查格式');
  }
  return { rules, warnings, errors };
}

// Exported for unit testing / reuse.
export { translateExpression, normalizePath };
