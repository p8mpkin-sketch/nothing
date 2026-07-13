import React, { useState, useEffect, useCallback, useRef } from 'react'
import './index.css'
import { AI_PROVIDERS, getProvider } from '../utils/aiProviders'
import { parseFingerprints } from '../utils/fingerprintImporter'

const FP_PLACEHOLDER = `header_contains_with_cookie:
  request:
    method: GET
    path: /
    headers:
      Cookie: rememberMe=true
  expression: response.raw_header.bcontains(b'=deleteMe') || response.raw_header.bcontains(b'shiro-cas')`

// 指纹格式导入弹窗（xray / afrog 风格 CEL 表达式 → 主动探测规则）
function FpImportModal({ onImport, onCancel }) {
  const [text, setText] = useState('')
  const [namePrefix, setNamePrefix] = useState('')
  const [result, setResult] = useState(null) // { rules, warnings, errors }

  const handleParse = () => {
    if (!text.trim()) { setResult({ rules: [], warnings: [], errors: ['请粘贴指纹内容'] }); return }
    setResult(parseFingerprints(text, { namePrefix: namePrefix.trim() }))
  }

  const handleConfirm = () => {
    if (!result || result.rules.length === 0) return
    const withIds = result.rules.map((r, i) => ({ ...r, id: Date.now() + i }))
    onImport(withIds)
    onCancel()
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onCancel()}>
      <div className="modal-box">
        <div className="modal-title">指纹格式导入</div>
        <div className="modal-hint" style={{ marginBottom: 10 }}>
          粘贴 CEL 表达式指纹（xray / afrog 风格，如 shiro、xxl-job），自动转为主动探测规则。
          支持 &amp;&amp; / || / 括号嵌套、contains/bcontains、raw_header/body 及状态码，可一次粘贴多个。
        </div>

        <div className="modal-field">
          <label className="modal-label">名称前缀 <span className="modal-label-hint">（可选，留空用指纹键名）</span></label>
          <input className="modal-input" placeholder="例如: shiro" value={namePrefix}
            onChange={e => setNamePrefix(e.target.value)} />
        </div>

        <div className="modal-field">
          <label className="modal-label">指纹内容 (YAML)</label>
          <textarea className="modal-input" placeholder={FP_PLACEHOLDER}
            style={{ minHeight: 180, resize: 'vertical', fontFamily: 'monospace', fontSize: '0.78rem' }}
            value={text} onChange={e => { setText(e.target.value); setResult(null) }} />
        </div>

        {result && (
          <div className="modal-field">
            {result.errors.length > 0 && (
              <div style={{ color: 'var(--danger-color, #ef4444)', fontSize: '0.8rem' }}>
                {result.errors.map((er, i) => <div key={i}>✕ {er}</div>)}
              </div>
            )}
            {result.rules.length > 0 && (
              <div className="modal-hint" style={{ maxHeight: 120, overflowY: 'auto' }}>
                <b>解析成功 {result.rules.length} 条：</b>
                {result.rules.map((r, i) => (
                  <div key={i} style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    • {r.name} — Active {r.probePath} [{r.matchScope === 'response_header' ? '响应头' : '响应体'}/{r.matchType}]
                  </div>
                ))}
              </div>
            )}
            {result.warnings.length > 0 && (
              <div style={{ color: '#d97706', fontSize: '0.75rem', marginTop: 6 }}>
                {result.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
              </div>
            )}
          </div>
        )}

        <div className="modal-actions">
          <button className="modal-cancel" onClick={onCancel}>取消</button>
          {result && result.rules.length > 0
            ? <button className="modal-save" onClick={handleConfirm}>确认导入 {result.rules.length} 条</button>
            : <button className="modal-save" onClick={handleParse}>解析预览</button>}
        </div>
      </div>
    </div>
  )
}

const TABS = [
  { id: 'scan', label: '扫描' },
  { id: 'backup', label: '备份文件' },
  { id: 'fingerprint', label: '指纹' },
  { id: 'site', label: '站点' },
  { id: 'rules', label: '规则引擎' },
  { id: 'logs', label: '命中日志' },
  { id: 'exclusion', label: '排除' },
  { id: 'settings', label: '设置' },
]

const SCAN_LABELS = {
  absoluteApi: 'API(绝对路径)',
  api: 'API(相对路径)',
  ip: '内网 IP',
  credential: '凭据/密钥',
  jwt: 'JWT Token',
  idKey: 'ID 密钥',
  idcard: '身份证',
  phone: '手机号',
  email: '邮箱',
  path: '内部路径',
  docFile: '文档文件',
  route: '前端路由',
  moduleFile: '模块文件(chunk)',
  domain: '域名',
  iframe: 'Iframe',
  image: '图片/音频',
  jsFile: 'JS 文件',
  url: 'URL',

  // Reflected XSS evidence (collected by content / background probe)
  pageParamSample: 'URL 参数样本',
  inlineScriptSnippet: '内联脚本片段(命中)',
  inlineScriptProbeSnippet: '内联脚本片段(探针)',
  inlineScriptSinkSnippet: '内联脚本片段(sink)',
}

const SCAN_RISK = {
  credential: 'high', jwt: 'high', idKey: 'high', idcard: 'high',
  ip: 'medium', email: 'medium', phone: 'medium', path: 'medium',
  absoluteApi: 'low', api: 'low', url: 'low', route: 'low', moduleFile: 'low', docFile: 'low',
  domain: 'low', jsFile: 'low', image: 'low', iframe: 'low',

  // Reflected XSS evidence
  pageParamSample: 'low',
  inlineScriptSnippet: 'low',
  inlineScriptProbeSnippet: 'low',
  inlineScriptSinkSnippet: 'low',
}

const SCAN_COLOR = {
  credential: 'red', jwt: 'red', idKey: 'red', idcard: 'red',
  ip: 'yellow', email: 'yellow', phone: 'yellow', path: 'yellow', docFile: 'orange',
  absoluteApi: 'blue', api: 'blue', url: 'blue', route: 'green', moduleFile: 'green',
  domain: 'blue', jsFile: 'yellow', image: 'blue', iframe: 'blue',

  // Reflected XSS evidence
  pageParamSample: 'gray',
  inlineScriptSnippet: 'gray',
  inlineScriptProbeSnippet: 'gray',
  inlineScriptSinkSnippet: 'gray',
}

const RISK_ORDER = { high: 0, medium: 1, low: 2 }

const RISK_GROUPS = {
  high: ['credential', 'jwt', 'idKey', 'idcard'],
  medium: ['ip', 'email', 'phone', 'path'],
  low: ['absoluteApi', 'api', 'route', 'moduleFile', 'docFile', 'url', 'domain', 'jsFile', 'image', 'iframe', 'pageParamSample', 'inlineScriptSnippet', 'inlineScriptProbeSnippet', 'inlineScriptSinkSnippet'],
}
const RISK_LABEL = { high: 'HIGH', medium: 'MED', low: 'LOW' }
const RISK_CN = { high: '高危', medium: '中危', low: '低危' }

// For "copy all": strip the "[SOURCE] value | CONTEXT: …" wrapper on credential-type
// items so the copied text is just the clean values.
function extractCopyValue(key, item) {
  if ((key === 'credential' || key === 'jwt' || key === 'idKey') && item.startsWith('[') && item.includes(']')) {
    const m = item.match(/^\[[^\]]+\]\s*(.+?)(?:\s*\|\s*CONTEXT:.*)?$/)
    return m ? m[1] : item
  }
  return item
}

const FP_LABELS = {
  server: '服务器',
  os: '操作系统',
  technology: '技术栈',
  framework: '框架',
  security: '安全头',
  cdn: 'CDN',
  analytics: '统计分析',
  builder: '建站工具',
}

function Badge({ color, children }) {
  return <span className={`badge badge-${color}`}>{children}</span>
}

function CollapseSection({ title, count, colorClass, percent, risk, onCopyAll, children }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="collapse-section">
      <button className="collapse-header" onClick={() => setOpen(o => !o)}>
        <span className="collapse-title">
          <span className={`collapse-dot ${colorClass}`}></span>
          {title}
          <span className="collapse-count">{count}</span>
          {risk && <span className={`risk-tag ${risk}`}>{risk === 'high' ? '高危' : risk === 'medium' ? '中危' : '低危'}</span>}
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {onCopyAll && (
            <span className="copy-all-btn" onClick={e => { e.stopPropagation(); onCopyAll() }}>
              复制全部
            </span>
          )}
          <span className="collapse-arrow">{open ? '▾' : '▸'}</span>
        </span>
      </button>
      {percent !== undefined && (
        <div className="collapse-progress">
          <div className={`collapse-progress-fill ${colorClass}`} style={{ width: `${Math.max(percent, 1)}%` }} />
        </div>
      )}
      {open && <div className="collapse-body">{children}</div>}
    </div>
  )
}

// ── Vuln Item (可展开的漏洞卡片) ──────────────────────────────────────────────
function VulnItem({ v }) {
  const [open, setOpen] = useState(false)
  const sev = v.severity === 'high' ? 'high' : v.severity === 'medium' ? 'medium' : 'low'
  const sevLabel = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }[sev]
  const confidence = v.confidence || 0
  const confidencePercent = Math.round(confidence * 100)
  const confidenceColor = confidence >= 0.8 ? 'var(--green)' : confidence >= 0.6 ? 'var(--yellow)' : 'var(--text3)'

  return (
    <div className={`vuln-item ${open ? 'open' : ''}`}>
      <div className="vuln-item-header" onClick={() => setOpen(o => !o)}>
        <span className="vuln-arrow">{open ? '▾' : '▸'}</span>
        <span className={`risk-tag ${sev}`}>{sevLabel}</span>
        {confidence > 0 && (
          <span className="confidence-badge" style={{
            background: confidenceColor,
            color: 'white',
            padding: '2px 6px',
            borderRadius: '3px',
            fontSize: '0.65rem',
            fontWeight: 600,
            marginLeft: 4
          }}>
            {confidencePercent}%
          </span>
        )}
        <span className="vuln-type">{v.type}</span>
        {v.verified && (
          <span style={{ background: 'var(--green)', color: 'white', padding: '2px 6px', borderRadius: 3, fontSize: '0.62rem', fontWeight: 700, marginLeft: 4 }}
            title="已在后台实测触发弹窗">✓ 已验证弹窗</span>
        )}
        {v.verdict === 'waf_blocked' && (
          <span style={{ background: '#eab308', color: 'black', padding: '2px 6px', borderRadius: 3, fontSize: '0.62rem', fontWeight: 700, marginLeft: 4 }}
            title="POC 全部被 WAF 拦截，反射点可能存在">🛡️ WAF 拦截</span>
        )}
        {v.verdict === 'bypassing_ai' && (
          <span style={{ background: '#6366f1', color: 'white', padding: '2px 6px', borderRadius: 3, fontSize: '0.62rem', fontWeight: 700, marginLeft: 4 }}
            title="AI 正在尝试绕过 WAF">⏳ AI 绕过中</span>
        )}
        {v.verdict === 'bypass_failed' && (
          <span style={{ background: '#ef4444', color: 'white', padding: '2px 6px', borderRadius: 3, fontSize: '0.62rem', fontWeight: 700, marginLeft: 4 }}
            title="AI 绕过失败，当前 WAF 防护较强">⛔ 绕过失败</span>
        )}
        {v.chain && <span className="vuln-chain">{v.chain}</span>}
        <span className="vuln-expand-hint">{open ? '收起' : '详情'}</span>
      </div>
      {open && (
        <div className="vuln-item-body">
          {v.file && (
            <div className="vuln-section">
              <div className="vuln-section-label">文件</div>
              <code className="vuln-code" style={{ color: 'var(--text2)', background: 'var(--bg-subtle)', border: '1px solid var(--border)' }}>{v.file}</code>
            </div>
          )}
          {confidence > 0 && (
            <div className="vuln-section">
              <div className="vuln-section-label">置信度</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ flex: 1, height: 6, background: 'var(--bg-subtle)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    width: `${confidencePercent}%`,
                    height: '100%',
                    background: confidenceColor,
                    transition: 'width 0.3s ease'
                  }} />
                </div>
                <span style={{ fontSize: '0.75rem', color: confidenceColor, fontWeight: 600 }}>
                  {confidencePercent}%
                </span>
              </div>
            </div>
          )}
          {v.analysis && (
            <div className="vuln-section">
              <div className="vuln-section-label" style={{ color: 'var(--accent)' }}>分析过程</div>
              <div className="vuln-section-text">{v.analysis}</div>
            </div>
          )}
          {v.description && (
            <div className="vuln-section">
              <div className="vuln-section-label">漏洞说明</div>
              <div className="vuln-section-text">{v.description}</div>
            </div>
          )}
          {v.source && (
            <div className="vuln-section">
              <div className="vuln-section-label">污点源 (Source)</div>
              <code className="vuln-code red">{v.source}</code>
            </div>
          )}
          {v.sink && (
            <div className="vuln-section">
              <div className="vuln-section-label">危险点 (Sink)</div>
              <code className="vuln-code red">{v.sink}</code>
            </div>
          )}
          {(v.poc || (Array.isArray(v.pocs) && v.pocs.length > 0)) && (
            <div className="vuln-section">
              <div className="vuln-section-label" style={{ color: 'var(--green)' }}>
                POC (可直接使用){v.verified ? ' · ✓ 已验证弹窗' : ''}
              </div>
              {(() => {
                const list = (Array.isArray(v.pocs) && v.pocs.length > 0)
                  ? v.pocs.slice(0, 10)
                  : (v.poc ? [v.poc] : [])
                const verifiedSet = new Set(Array.isArray(v.verifiedPocs) ? v.verifiedPocs : [])
                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {list.map((p, idx) => {
                      const isVerified = verifiedSet.has(p)
                      return (
                        <div key={idx} style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                          <code className="vuln-code green" style={{ flex: 1, borderColor: isVerified ? 'var(--green)' : undefined }}>
                            {isVerified && <span style={{ color: 'var(--green)', fontWeight: 700, marginRight: 4 }}>✓</span>}
                            {p}
                          </code>
                          <button className="copy-btn-sm" style={{ marginTop: 4, alignSelf: 'flex-start' }}
                            onClick={() => navigator.clipboard.writeText(p)} title={isVerified ? '已实测弹窗 · 复制 POC' : '复制 POC'}>
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                          </button>
                        </div>
                      )
                    })}
                  </div>
                )
              })()}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Backup Tab ────────────────────────────────────────────────────────────────
function BackupTab() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all') // all, backup, vcs, sensitive
  const [scanStatus, setScanStatus] = useState(null) // { status, progress, total, scanned }

  useEffect(() => {
    loadFindings()
    loadStatus()

    // Listen for new findings and status updates
    const listener = (message) => {
      if (message.action === 'BACKUP_FINDINGS') {
        loadFindings()
      }
      if (message.action === 'BACKUP_STATUS') {
        setScanStatus(message.status)
      }
    }
    chrome.runtime.onMessage.addListener(listener)
    return () => chrome.runtime.onMessage.removeListener(listener)
  }, [])

  const loadFindings = () => {
    setLoading(true)
    chrome.runtime.sendMessage({ action: 'GET_BACKUP_FINDINGS' }, (response) => {
      setFindings(response?.findings || [])
      setLoading(false)
    })
  }

  const loadStatus = () => {
    chrome.runtime.sendMessage({ action: 'GET_BACKUP_STATUS' }, (response) => {
      setScanStatus(response?.status || null)
    })
  }

  const filteredFindings = findings.filter(f => {
    if (filter === 'all') return true
    return f.type === filter
  })

  const groupedByType = {
    vcs: filteredFindings.filter(f => f.type === 'vcs'),
    sensitive: filteredFindings.filter(f => f.type === 'sensitive'),
    backup: filteredFindings.filter(f => f.type === 'backup'),
  }

  const formatSize = (bytes) => {
    if (!bytes || bytes === 0) return '未知'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  }

  const getTypeLabel = (type) => {
    const labels = {
      vcs: '版本控制泄露',
      sensitive: '敏感文件',
      backup: '备份文件',
    }
    return labels[type] || type
  }

  const getTypeColor = (type) => {
    const colors = {
      vcs: 'var(--red)',
      sensitive: 'var(--orange)',
      backup: 'var(--yellow)',
    }
    return colors[type] || 'var(--text3)'
  }

  if (loading) {
    return <div className="loading-state">加载中...</div>
  }

  const getStatusText = () => {
    if (!scanStatus) return null
    if (scanStatus.status === 'disabled') return '扫描已禁用'
    if (scanStatus.status === 'scanning') return `扫描中... ${scanStatus.progress}%`
    if (scanStatus.status === 'completed') return '扫描完成'
    if (scanStatus.status === 'error') return '扫描出错'
    return null
  }

  const getStatusColor = () => {
    if (!scanStatus) return 'var(--text3)'
    if (scanStatus.status === 'disabled') return 'var(--text3)'
    if (scanStatus.status === 'scanning') return 'var(--primary)'
    if (scanStatus.status === 'completed') return 'var(--green)'
    if (scanStatus.status === 'error') return 'var(--red)'
    return 'var(--text3)'
  }

  return (
    <div className="scan-tab">
      <div className="scan-overview" style={{ alignItems: 'center' }}>
        <div className="scan-overview-left" style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
          <span className="scan-count" style={{ fontSize: '2rem', fontWeight: 700 }}>{findings.length}</span>
          <span className="scan-label" style={{ fontSize: '0.9rem', color: 'var(--text2)' }}>个泄露</span>
        </div>
        <div className="scan-overview-right">
          <button
            className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            全部 ({findings.length})
          </button>
          <button
            className={`filter-btn ${filter === 'vcs' ? 'active' : ''}`}
            onClick={() => setFilter('vcs')}
          >
            VCS ({groupedByType.vcs.length})
          </button>
          <button
            className={`filter-btn ${filter === 'sensitive' ? 'active' : ''}`}
            onClick={() => setFilter('sensitive')}
          >
            敏感 ({groupedByType.sensitive.length})
          </button>
          <button
            className={`filter-btn ${filter === 'backup' ? 'active' : ''}`}
            onClick={() => setFilter('backup')}
          >
            备份 ({groupedByType.backup.length})
          </button>
        </div>
      </div>

      {scanStatus && (
        <div className="scan-status-bar" style={{
          padding: '8px 12px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: '4px',
          marginBottom: '12px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}>
          <span style={{
            fontSize: '0.8rem',
            color: getStatusColor(),
            fontWeight: 500,
          }}>
            {getStatusText()}
          </span>
          {scanStatus.status === 'scanning' && scanStatus.total > 0 && (
            <>
              <div style={{
                flex: 1,
                height: '6px',
                background: 'var(--bg-subtle)',
                borderRadius: '3px',
                overflow: 'hidden',
              }}>
                <div style={{
                  width: `${scanStatus.progress}%`,
                  height: '100%',
                  background: 'var(--primary)',
                  transition: 'width 0.3s ease',
                }}></div>
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text3)' }}>
                {scanStatus.scanned} / {scanStatus.total}
              </span>
            </>
          )}
        </div>
      )}

      {filteredFindings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <p>{filter === 'all' ? '未发现泄露' : `未发现${getTypeLabel(filter)}`}</p>
          <small>扫描完成后会自动显示结果</small>
        </div>
      ) : (
        <div className="scan-results">
          {filteredFindings.map((finding, idx) => (
            <div key={idx} className="backup-finding-item">
              <div className="backup-finding-header">
                <span
                  className="backup-type-badge"
                  style={{
                    background: getTypeColor(finding.type),
                    color: 'white',
                    padding: '2px 8px',
                    borderRadius: '3px',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                  }}
                >
                  {getTypeLabel(finding.type)}
                </span>
                <span
                  className="backup-status-badge"
                  style={{
                    background: finding.status === 200 ? 'var(--green)' : 'var(--orange)',
                    color: 'white',
                    padding: '2px 8px',
                    borderRadius: '3px',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                  }}
                >
                  {finding.status}
                </span>
                <span className="backup-size" style={{ color: 'var(--text3)', fontSize: '0.75rem' }}>
                  {formatSize(finding.size)}
                </span>
              </div>
              <div className="backup-finding-url">
                <a
                  href={finding.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    color: 'var(--primary)',
                    textDecoration: 'none',
                    fontSize: '0.8rem',
                    wordBreak: 'break-all',
                  }}
                  title={finding.url}
                >
                  {finding.url}
                </a>
              </div>
              <div className="backup-finding-meta" style={{
                fontSize: '0.7rem',
                color: 'var(--text3)',
                marginTop: '4px',
              }}>
                <span>类型: {finding.contentType}</span>
                <span style={{ marginLeft: '12px' }}>
                  发现时间: {new Date(finding.foundAt).toLocaleTimeString()}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Scan Tab ──────────────────────────────────────────────────────────────────
// Compact site-info strip shown at the top of the Scan tab (domain / IP / ICP).
function SiteInfoPanel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    chrome.runtime.sendMessage({ action: 'GET_SITE_ANALYSIS' }, (res) => { setData(res || {}); setLoading(false) })
  }, [])
  useEffect(() => { load() }, [load])

  const hostname = data?.hostname || ''
  const isInternal = !!data?.isInternal
  const ip = data?.resolvedIp || data?.ip?.data?.ip || ''
  const loc = data?.ip?.data?.location || ''
  const icp = data?.icp
  const icpOk = icp && !icp.error && icp.code === 200
  const isHttps = data?.protocol === 'https:'

  const mono = { fontFamily: "'JetBrains Mono', monospace" }
  const labelStyle = { color: 'var(--text3)', marginRight: 6, fontSize: '0.7rem' }

  // ICP line content depends on state (internal / IP / filed / not filed / loading).
  let icpNode
  if (loading) icpNode = <span style={{ color: 'var(--text3)' }}>查询中…</span>
  else if (icpOk) icpNode = <>
    <span style={{ color: 'var(--text)', fontWeight: 500 }}>{icp.icp}</span>
    {icp.unit && <span style={{ color: 'var(--text2)', marginLeft: 8 }}>{icp.unit}{icp.type ? `（${icp.type}）` : ''}</span>}
  </>
  else if (icp?.code === 0) icpNode = <span style={{ color: 'var(--text3)' }}>IP 地址无需备案</span>
  else icpNode = <span style={{ color: 'var(--text3)' }}>未查询到备案信息</span>

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '9px 11px', marginBottom: 8, fontSize: '0.76rem', color: 'var(--text)', boxShadow: 'var(--shadow)' }}>
      {/* 域名 + 协议 + 内网标记 + 刷新 */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: '0.72rem' }}>{isHttps ? '🔒' : '⚠️'}</span>
        <span style={{ ...mono, fontWeight: 600, color: 'var(--text)', fontSize: '0.8rem', wordBreak: 'break-all' }}>{hostname || '—'}</span>
        {isInternal && (
          <span style={{ fontSize: '0.66rem', color: 'var(--text2)', background: 'var(--bg-subtle)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 6px', flexShrink: 0 }}>内网</span>
        )}
        <button onClick={load} disabled={loading} title="刷新站点信息"
          style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: 'var(--text3)', cursor: 'pointer', fontSize: '0.9rem', lineHeight: 1, padding: 2, flexShrink: 0 }}>↻</button>
      </div>

      {isInternal ? (
        // 内网 / 自定义域名:无公网备案与归属信息
        <div style={{ marginTop: 5, color: 'var(--text3)' }}>
          内网地址 / 自定义域名，无公网备案与归属信息
        </div>
      ) : (
        <>
          {/* IP + 归属 */}
          {(ip || !loading) && (
            <div style={{ marginTop: 5, display: 'flex', alignItems: 'baseline', flexWrap: 'wrap' }}>
              <span style={labelStyle}>IP</span>
              <span style={{ ...mono, color: ip ? 'var(--text)' : 'var(--text3)' }}>{ip || (loading ? '—' : '未解析')}</span>
              {loc && <span style={{ color: 'var(--text2)', marginLeft: 8 }}>{loc}</span>}
            </div>
          )}
          {/* ICP 备案 */}
          <div style={{ marginTop: 5, display: 'flex', alignItems: 'baseline', flexWrap: 'wrap' }}>
            <span style={labelStyle}>备案</span>
            {icpNode}
          </div>
        </>
      )}
    </div>
  )
}

function ScanTab() {
  const [data, setData] = useState({})
  const [loading, setLoading] = useState(true)
  const [vulnResult, setVulnResult] = useState(null)
  const [activeRisk, setActiveRisk] = useState(null)
  const [search, setSearch] = useState('')
  const [aiStatus, setAiStatus] = useState({})

  useEffect(() => {
    // Poll scan results every 4s (background AI filter updates them in place)
    const loadData = () => {
      chrome.runtime.sendMessage({ action: 'GET_SCAN_RESULTS' }, (res) => {
        setData(res?.data || {})
        setLoading(false)
      })
    }
    loadData()
    const t1 = setInterval(loadData, 4000)
    // Poll for background vuln analysis result every 3s
    const loadVulns = () => {
      chrome.runtime.sendMessage({ action: 'GET_VULN_RESULTS' }, (res) => {
        if (res?.data) setVulnResult(res.data)
      })
    }
    loadVulns()
    const t2 = setInterval(loadVulns, 3000)
    // Poll AI status every 2s
    const loadStatus = () => {
      chrome.runtime.sendMessage({ action: 'GET_AI_STATUS' }, (res) => {
        if (res?.status) setAiStatus(res.status)
      })
    }
    loadStatus()
    const t3 = setInterval(loadStatus, 2000)
    return () => { clearInterval(t1); clearInterval(t2); clearInterval(t3) }
  }, [])

  const displayData = data
  const total = Object.values(data).reduce((s, a) => s + a.length, 0)

  // Merge vuln results into risk groups as a special 'vuln' category
  const vulns = vulnResult?.vulnerabilities || []
  const vulnByRisk = { high: [], medium: [], low: [] }
  vulns.forEach(v => {
    const r = v.severity === 'high' ? 'high' : v.severity === 'medium' ? 'medium' : 'low'
    vulnByRisk[r].push(v)
  })

  const riskCounts = {
    high: RISK_GROUPS.high.reduce((s, k) => s + (displayData[k]?.length || 0), 0) + vulnByRisk.high.length,
    medium: RISK_GROUPS.medium.reduce((s, k) => s + (displayData[k]?.length || 0), 0) + vulnByRisk.medium.length,
    low: RISK_GROUPS.low.reduce((s, k) => s + (displayData[k]?.length || 0), 0) + vulnByRisk.low.length,
  }

  const effectiveRisk = activeRisk || ['high', 'medium', 'low'].find(r => riskCounts[r] > 0) || null

  const activeCategories = effectiveRisk
    ? RISK_GROUPS[effectiveRisk]
        .filter(k => (displayData[k]?.length || 0) > 0)
        .map(k => ({ key: k, items: displayData[k] || [], isVuln: false }))
    : []

  const filteredCategories = search
    ? activeCategories.map(({ key, items, isVuln }) => ({
        key, isVuln,
        items: items.filter(item => item.toLowerCase().includes(search.toLowerCase()))
      })).filter(({ items }) => items.length > 0)
    : activeCategories

  const activeVulns = effectiveRisk ? vulnByRisk[effectiveRisk] : []
  const filteredVulns = search
    ? activeVulns.filter(v => (v.type + v.description + v.chain).toLowerCase().includes(search.toLowerCase()))
    : activeVulns

  const VULN_TYPE_ORDER = ['Reflected XSS', 'DOM XSS', 'Open Redirect', 'SSRF']
  const vulnTypeRank = (t) => {
    const idx = VULN_TYPE_ORDER.indexOf(t)
    return idx === -1 ? 999 : idx
  }
  const groupedVulns = filteredVulns.reduce((acc, v) => {
    const t = (v.type || 'Other').trim()
    if (!acc[t]) acc[t] = []
    acc[t].push(v)
    return acc
  }, {})
  const groupedVulnEntries = Object.entries(groupedVulns)
    .sort((a, b) => {
      const ra = vulnTypeRank(a[0])
      const rb = vulnTypeRank(b[0])
      if (ra !== rb) return ra - rb
      return a[0].localeCompare(b[0])
    })

  const copyRiskGroup = (risk) => {
    // Vuln findings copy their primary POC (the directly-usable payload URL), one per line.
    const vulnLines = (vulnByRisk[risk] || [])
      .map(v => v.poc || (Array.isArray(v.pocs) && v.pocs[0]) || '')
      .filter(Boolean)
    const items = RISK_GROUPS[risk].flatMap(k => (displayData[k] || []).map(it => extractCopyValue(k, it)))
    const all = [...vulnLines, ...items]
    if (all.length === 0) return
    navigator.clipboard.writeText(all.join('\n'))
  }

  if (loading) return (
    <div className="scan-layout">
      <SiteInfoPanel />
      <div className="empty-state"><p>加载中...</p></div>
    </div>
  )

  const hasAnyData = total > 0 || vulns.length > 0

  return (
    <div className="scan-layout">
      <SiteInfoPanel />
      {/* Zone A */}
      <div className="scan-overview-bar">
        <div className="scan-overview-left">
          <span className="scan-total-number">{total + vulns.length}</span>
          <span className="scan-total-label">条发现</span>
          <div className="scan-risk-pills">
            {riskCounts.high > 0 && <span className="scan-risk-pill high"><span className="scan-risk-dot" />{riskCounts.high} 高危</span>}
            {riskCounts.medium > 0 && <span className="scan-risk-pill medium"><span className="scan-risk-dot" />{riskCounts.medium} 中危</span>}
            {riskCounts.low > 0 && <span className="scan-risk-pill low"><span className="scan-risk-dot" />{riskCounts.low} 低危</span>}
          </div>
        </div>
        <div className="scan-overview-right">
          {aiStatus.filter === 'analyzing' && <span className="ai-status-badge analyzing">⏳ AI 过滤中</span>}
          {aiStatus.filter === 'done' && <span className="ai-status-badge done">✓ AI 已过滤</span>}
          {aiStatus.filter === 'error' && <span className="ai-status-badge error">✗ AI 过滤失败</span>}
          {aiStatus.vuln === 'analyzing' && <span className="ai-status-badge analyzing">⏳ 漏洞分析中</span>}
          {aiStatus.vuln === 'done' && <span className="ai-status-badge done">✓ 漏洞分析完成</span>}
          {aiStatus.vuln === 'error' && <span className="ai-status-badge error">✗ 漏洞分析失败</span>}
          {aiStatus.verify === 'verifying' && <span className="ai-status-badge analyzing">⏳ POC 验证中</span>}
          {aiStatus.verify === 'done' && <span className="ai-status-badge done">✓ POC 已验证</span>}
        </div>
      </div>

      {!hasAnyData
        ? <div className="empty-state"><div className="empty-icon">🔍</div><p>暂无发现</p><small>访问网页后自动扫描</small></div>
        : <>
            {/* Zone B */}
            <div className="scan-risk-groups">
              {(['high', 'medium', 'low']).filter(r => riskCounts[r] > 0).map(risk => {
                const cats = RISK_GROUPS[risk].filter(k => (displayData[k]?.length || 0) > 0)
                const hasVulns = vulnByRisk[risk].length > 0
                return (
                  <div key={risk} className={`scan-risk-row ${effectiveRisk === risk ? 'active' : ''}`}
                    data-risk={risk} onClick={() => setActiveRisk(risk)}>
                    <span className="scan-risk-label">{RISK_LABEL[risk]}</span>
                    <span className="scan-risk-count">{riskCounts[risk]}</span>
                    <div className="scan-risk-cats">
                      {hasVulns && <span className="scan-risk-cat-pill" style={{ color: 'var(--red)', borderColor: 'rgba(239,68,68,0.3)' }}>漏洞</span>}
                      {cats.slice(0, hasVulns ? 2 : 3).map(k => (
                        <span key={k} className="scan-risk-cat-pill">{SCAN_LABELS[k] || k}</span>
                      ))}
                      {(cats.length - (hasVulns ? 2 : 3)) > 0 && <span className="scan-risk-cat-pill">+{cats.length - (hasVulns ? 2 : 3)}</span>}
                    </div>
                    <span className="copy-all-btn" onClick={e => { e.stopPropagation(); copyRiskGroup(risk) }}>复制全部</span>
                    <span className="scan-risk-chevron">{effectiveRisk === risk ? '▾' : '▸'}</span>
                  </div>
                )
              })}
            </div>

            {/* Zone C */}
            <div className="scan-detail-panel">
              {effectiveRisk && (
                <div className="scan-detail-header">
                  <span className="scan-detail-title">{RISK_CN[effectiveRisk]} · {riskCounts[effectiveRisk]} 条</span>
                  <input className="scan-search-input" placeholder="过滤..." value={search}
                    onChange={e => setSearch(e.target.value)} />
                </div>
              )}
              {/* Vuln items first */}
              {filteredVulns.length > 0 && (
                <div className="scan-category-cluster">
                  <div className="scan-category-label" style={{ color: 'var(--red)' }}>漏洞分析 <span style={{ fontFamily: 'JetBrains Mono', fontWeight: 400 }}>{filteredVulns.length}</span></div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {groupedVulnEntries.map(([type, items]) => (
                      <div key={type} className="vuln-type-group">
                        <div className="vuln-type-header">
                          <span className="vuln-type-title">{type}</span>
                          <span className="vuln-type-count">{items.length}</span>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          {items.map((v, i) => <VulnItem key={i} v={v} />)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* Regular scan items */}
              {filteredCategories.map(({ key, items }) => (
                <div key={key} className="scan-category-cluster">
                  <div className="scan-category-label" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>{SCAN_LABELS[key] || key} <span style={{ fontFamily: 'JetBrains Mono', fontWeight: 400 }}>{items.length}</span></span>
                    <span className="copy-all-btn" style={{ marginLeft: 'auto' }}
                      title={`复制全部 ${items.length} 条`}
                      onClick={() => navigator.clipboard.writeText(items.map(it => extractCopyValue(key, it)).join('\n'))}>
                      复制全部
                    </span>
                  </div>
                  <div className="scan-chips-wrap">
                    {items.map((item, i) => {
                      // Parse enhanced credential format: [SOURCE] value | CONTEXT: snippet
                      const isCredential = key === 'credential' || key === 'jwt' || key === 'idKey';
                      if (isCredential && item.includes('[') && item.includes(']')) {
                        const sourceMatch = item.match(/^\[([^\]]+)\]/);
                        const source = sourceMatch ? sourceMatch[1] : '';
                        const restMatch = item.match(/^\[[^\]]+\]\s*(.+?)(?:\s*\|\s*CONTEXT:\s*(.*))?$/);
                        const value = restMatch ? restMatch[1] : item;
                        const context = restMatch && restMatch[2] ? restMatch[2] : '';

                        // Extract URL from source if it's a JS file
                        let displaySource = source;
                        let fullUrl = '';
                        if (source.startsWith('JS:')) {
                          fullUrl = source.replace('JS:', '');
                          // Show only filename for display
                          const urlParts = fullUrl.split('/');
                          const filename = urlParts[urlParts.length - 1] || fullUrl;
                          displaySource = `JS:${filename}`;
                        } else if (source.startsWith('DYNAMIC_JS:')) {
                          fullUrl = source.replace('DYNAMIC_JS:', '');
                          const urlParts = fullUrl.split('/');
                          const filename = urlParts[urlParts.length - 1] || fullUrl;
                          displaySource = `DYNAMIC:${filename}`;
                        }

                        return (
                          <div key={i} className={`result-item item-${SCAN_COLOR[key] || 'blue'} credential-enhanced`}
                            style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '8px 10px', gap: 4 }}
                            onClick={() => navigator.clipboard.writeText(value)}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                              {source && (
                                <span style={{
                                  background: 'rgba(239,68,68,0.15)',
                                  color: 'var(--red)',
                                  padding: '2px 6px',
                                  borderRadius: '3px',
                                  fontSize: '0.65rem',
                                  fontWeight: 600,
                                  fontFamily: 'JetBrains Mono, monospace',
                                  cursor: fullUrl ? 'pointer' : 'default'
                                }}
                                title={fullUrl || displaySource}
                                onClick={(e) => {
                                  if (fullUrl) {
                                    e.stopPropagation();
                                    navigator.clipboard.writeText(fullUrl);
                                  }
                                }}>
                                  {displaySource}
                                </span>
                              )}
                              <span style={{ flex: 1, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                {value}
                              </span>
                            </div>
                            {context && (
                              <div style={{
                                fontSize: '0.7rem',
                                color: 'var(--text3)',
                                fontFamily: 'JetBrains Mono, monospace',
                                background: 'var(--bg-subtle)',
                                padding: '4px 6px',
                                borderRadius: '3px',
                                width: '100%',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }} title={context}>
                                {context}
                              </div>
                            )}
                          </div>
                        );
                      }

                      // Regular item
                      return (
                        <span key={i} className={`result-item item-${SCAN_COLOR[key] || 'blue'}`} title={item}
                          onClick={() => navigator.clipboard.writeText(item)}>{item}</span>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </>
      }
    </div>
  )
}

// ── Fingerprint Tab ───────────────────────────────────────────────────────────
const FP_COLOR = {
  server: 'blue', os: 'gray', technology: 'blue', framework: 'gray',
  security: 'green', cdn: 'gray', analytics: 'gray', builder: 'gray',
}

const CopyIcon = () => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
)

function FingerprintTab() {
  const [data, setData] = useState({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    chrome.runtime.sendMessage({ action: 'GET_FINGERPRINTS' }, (res) => {
      setData(res?.data || {})
      setLoading(false)
    })
  }, [])

  const categories = Object.entries(data).filter(([, v]) => v.length > 0)

  if (loading) return <div className="empty-state"><p>加载中...</p></div>
  if (categories.length === 0) return (
    <div className="empty-state">
      <div className="empty-icon">🔎</div>
      <p>暂无指纹信息</p>
      <small>访问网页后自动识别</small>
    </div>
  )

  // Build summary: server + technology highlights
  const serverItems = data.server || []
  const techItems = data.technology || []
  const summaryItems = [...serverItems, ...techItems].slice(0, 4)

  return (
    <div className="tab-content">
      {summaryItems.length > 0 && (
        <div className="fp-summary">
          <span className="fp-summary-label">识别到</span>
          {summaryItems.map((item, i) => (
            <Badge key={i} color={serverItems.includes(item) ? 'blue' : 'gray'}>
              {item.name}{item.version ? ` ${item.version}` : ''}
            </Badge>
          ))}
          {categories.reduce((s, [, v]) => s + v.length, 0) > summaryItems.length && (
            <span style={{ fontSize: '0.7rem', color: 'var(--text3)' }}>
              +{categories.reduce((s, [, v]) => s + v.length, 0) - summaryItems.length} 更多
            </span>
          )}
        </div>
      )}
      {categories.map(([cat, items]) => (
        <CollapseSection
          key={cat}
          title={FP_LABELS[cat] || cat}
          count={items.length}
          colorClass={FP_COLOR[cat] || 'gray'}
          onCopyAll={() => navigator.clipboard.writeText(items.map(i => i.version ? `${i.name} ${i.version}` : i.name).join('\n'))}
        >
          {cat === 'security' ? (
            <div className="badge-group">
              {items.map((item, i) => (
                <Badge key={i} color="green">{item.name}</Badge>
              ))}
            </div>
          ) : (
            <div className="fp-list">
              {items.map((item, i) => (
                <div key={i} className="fp-item"
                  title={`点击复制: ${item.version ? `${item.name} ${item.version}` : item.value || item.name}`}
                  onClick={() => navigator.clipboard.writeText(item.version ? `${item.name} ${item.version}` : item.value || item.name)}>
                  <span className="fp-name">{item.name}</span>
                  {item.version && <span className="fp-version">{item.version}</span>}
                  {item.value && !item.version && (
                    <span className="fp-version" title={item.value}>
                      {item.value.length > 24 ? item.value.slice(0, 24) + '…' : item.value}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </CollapseSection>
      ))}
    </div>
  )
}

// ── Site Tab ──────────────────────────────────────────────────────────────────
function SiteTab() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    chrome.runtime.sendMessage({ action: 'GET_SITE_ANALYSIS' }, (res) => {
      setData(res || {})
      setLoading(false)
    })
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return (
    <div className="tab-content center">
      <div className="site-loading">
        <span>查询站点信息中...</span>
      </div>
    </div>
  )

  if (data?.error) return <div className="empty-state"><p>查询失败: {data.error}</p><button className="reload-btn" style={{marginTop:12}} onClick={load}>重试</button></div>

  const icp = data?.icp
  const ip = data?.ip
  const hostname = data?.hostname || ''
  const isHttps = data?.protocol === 'https:' || hostname.startsWith('https')

  return (
    <div className="tab-content">
      <div className="site-section-title">基本信息</div>
      <div className="site-row">
        <div className="site-section">
          <div className="site-label">域名</div>
          <div className="site-value mono">{hostname || '-'}</div>
        </div>
        <div className="site-section">
          <div className="site-label">协议</div>
          <div className="site-value">
            <span className={`site-protocol ${data?.protocol === 'https:' ? 'secure' : 'insecure'}`}>
              {data?.protocol === 'https:' ? '🔒 HTTPS' : '⚠ HTTP'}
            </span>
          </div>
        </div>
      </div>
      <div className="site-section">
        <div className="site-label">IP 地址</div>
        <div className="site-value mono">{data?.resolvedIp || data?.ip?.data?.ip || '-'}</div>
      </div>
      {ip && !ip.error && (
        <>
          <div className="site-section-title">IP 归属</div>
          <div className="site-section">
            <div className="site-value">
              {ip.data?.location || '-'}
            </div>
            {ip.data?.isp && <div className="site-sub">{ip.data.isp}{ip.data.net ? ` · ${ip.data.net}` : ''}</div>}
          </div>
        </>
      )}
      {icp && !icp.error && icp.code === 200 && (
        <>
          <div className="site-section-title">ICP 备案</div>
          <div className="site-section">
            <div className="site-value">{icp.icp || '未备案'}</div>
            {icp.unit && <div className="site-sub">{icp.unit}{icp.type ? ` · ${icp.type}` : ''}</div>}
          </div>
        </>
      )}
      {icp && (icp.error || icp.code !== 200) && (
        <>
          <div className="site-section-title">ICP 备案</div>
          <div className="site-section">
            <div className="site-value" style={{ color: 'var(--text3)' }}>未备案 / 查询失败</div>
          </div>
        </>
      )}
      <button className="reload-btn" onClick={load} disabled={loading}>
        {loading ? '刷新中...' : '刷新'}
      </button>
    </div>
  )
}

// ── Rule Modal ────────────────────────────────────────────────────────────────
function RuleModal({ rule, onSave, onCancel }) {
  const [r, setR] = useState(rule)
  const [mode, setMode] = useState(rule.probePath !== undefined ? (rule.probePath ? 'active' : 'passive') : 'passive')

  const handleModeChange = (m) => {
    setMode(m)
    if (m === 'passive') setR(prev => ({ ...prev, probePath: '', matchScope: '', matchStatusCode: '', matchCondition: 'and' }))
    else setR(prev => ({ ...prev, probePath: prev.probePath || '', matchScope: prev.matchScope || 'body', scope: '' }))
  }

  const handleSave = () => {
    if (!r.name) { alert('请填写规则名称'); return }
    if (!r.pattern && r.matchType !== 'regex') { alert('请填写匹配内容'); return }
    onSave({ ...r, id: r.id || Date.now() })
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onCancel()}>
      <div className="modal-box">
        <div className="modal-title">{r.id ? '编辑规则' : '新建规则'}</div>

        <div className="modal-field">
          <label className="modal-label">规则名称</label>
          <input className="modal-input" placeholder="例如: 探测 Actuator 端点" value={r.name}
            onChange={e => setR(p => ({ ...p, name: e.target.value }))} />
        </div>

        <div className="modal-field">
          <label className="modal-label">检测模式</label>
          <div className="modal-mode-toggle">
            <button className={`mode-btn ${mode === 'passive' ? 'active' : ''}`} onClick={() => handleModeChange('passive')}>被动监测</button>
            <button className={`mode-btn ${mode === 'active' ? 'active' : ''}`} onClick={() => handleModeChange('active')}>主动探测</button>
          </div>
          <div className="modal-hint">
            {mode === 'passive'
              ? '浏览时自动检查流量，适合发现 URL/响应头/页面内容中的敏感信息。'
              : '主动向当前域名发送请求探测隐藏路径，多路径用 | 分隔，如 /actuator/|/actuator/env。'}
          </div>
        </div>

        {mode === 'passive' && (
          <div className="modal-field">
            <label className="modal-label">检查范围</label>
            <select className="modal-select" value={r.scope || 'url'} onChange={e => setR(p => ({ ...p, scope: e.target.value }))}>
              <option value="url">URL 路径</option>
              <option value="header">HTTP 头 (响应头)</option>
              <option value="body">响应体 (页面内容)</option>
            </select>
          </div>
        )}

        {mode === 'active' && (
          <>
            <div className="modal-field">
              <label className="modal-label">探测路径 <span className="modal-label-hint">（多路径用 | 分隔，留空探测当前 URL）</span></label>
              <input className="modal-input" placeholder="/actuator/|/actuator/env|/admin"
                value={r.probePath || ''} onChange={e => setR(p => ({ ...p, probePath: e.target.value }))} />
            </div>
            <div className="modal-field">
              <label className="modal-label">自定义请求头 <span className="modal-label-hint">（可选，每行一个，格式：Key: Value）</span></label>
              <textarea className="modal-input" placeholder="Cookie: rememberMe=test&#10;User-Agent: CustomBot"
                style={{ minHeight: 60, resize: 'vertical', fontFamily: 'monospace', fontSize: '0.8rem' }}
                value={r.requestHeaders || ''} onChange={e => setR(p => ({ ...p, requestHeaders: e.target.value }))} />
            </div>
            <div className="modal-field">
              <label className="modal-label">匹配范围</label>
              <select className="modal-select" value={r.matchScope || 'body'} onChange={e => setR(p => ({ ...p, matchScope: e.target.value }))}>
                <option value="body">响应体</option>
                <option value="response_header">响应头</option>
              </select>
            </div>
            <div className="modal-field">
              <label className="modal-label" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input type="checkbox" checked={!!r.hostDedupe}
                  onChange={e => setR(p => ({ ...p, hostDedupe: e.target.checked }))} />
                整站指纹（同域名只报一次）
              </label>
              <div className="modal-hint">开启后:该规则在一个域名首次命中即停止,避免整站框架(如 shiro)每个目录都告警。特定路径规则(如 /actuator/)建议关闭,以免 nginx 子路径转发漏报。</div>
            </div>
            <div className="modal-row">
              <div className="modal-field">
                <label className="modal-label">状态码匹配 <span className="modal-label-hint">（如 200,403，留空忽略）</span></label>
                <input className="modal-input" placeholder="200,403"
                  value={r.matchStatusCode || ''} onChange={e => setR(p => ({ ...p, matchStatusCode: e.target.value }))} />
              </div>
              <div className="modal-field">
                <label className="modal-label">匹配逻辑</label>
                <select className="modal-select" value={r.matchCondition || 'and'}
                  onChange={e => setR(p => ({ ...p, matchCondition: e.target.value }))}
                  disabled={!r.matchStatusCode}>
                  <option value="and">AND（状态码 + 内容）</option>
                  <option value="or">OR（状态码 或 内容）</option>
                </select>
              </div>
            </div>
          </>
        )}

        <div className="modal-row">
          <div className="modal-field">
            <label className="modal-label">匹配方式</label>
            <select className="modal-select" value={r.matchType || 'contains'} onChange={e => setR(p => ({ ...p, matchType: e.target.value }))}>
              <option value="contains">包含文本</option>
              <option value="regex">正则表达式</option>
            </select>
          </div>
        </div>

        <div className="modal-field">
          <label className="modal-label">匹配内容 <span className="modal-label-hint">（Regex 模式输入 ^$ 匹配空响应体）</span></label>
          <input className="modal-input" placeholder={r.matchType === 'regex' ? '^.*sensitive.*' : '输入要查找的文本'}
            value={r.pattern} onChange={e => setR(p => ({ ...p, pattern: e.target.value }))} />
        </div>

        <div className="modal-actions">
          <button className="modal-cancel" onClick={onCancel}>取消</button>
          <button className="modal-save" onClick={handleSave}>保存规则</button>
        </div>
      </div>
    </div>
  )
}

// ── Rules Tab ─────────────────────────────────────────────────────────────────
function RulesTab() {
  const [rules, setRules] = useState([])
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState(null)
  const [fpOpen, setFpOpen] = useState(false)
  const [selected, setSelected] = useState(new Set())
  const [page, setPage] = useState(1)
  const importRef = useRef(null)
  const PER_PAGE = 10

  useEffect(() => {
    chrome.storage.local.get('rules', d => setRules(d.rules || []))
  }, [])

  const persist = (newRules) => {
    chrome.storage.local.set({ rules: newRules }, () => setRules(newRules))
  }

  const saveRule = (rule) => {
    const idx = rules.findIndex(r => r.id === rule.id)
    const next = idx >= 0 ? rules.map((r, i) => i === idx ? rule : r) : [...rules, rule]
    persist(next)
    setEditing(null)
  }

  const deleteRule = (id) => {
    if (confirm('确定删除此规则？')) persist(rules.filter(r => r.id !== id))
  }

  const bulkDelete = () => {
    if (selected.size === 0) return
    if (confirm(`确定删除选中的 ${selected.size} 条规则？`)) {
      persist(rules.filter(r => !selected.has(r.id)))
      setSelected(new Set())
    }
  }

  const toggleSelect = (id) => {
    setSelected(prev => {
      const s = new Set(prev)
      s.has(id) ? s.delete(id) : s.add(id)
      return s
    })
  }

  const toggleSelectAll = () => {
    if (selected.size === paged.length) setSelected(new Set())
    else setSelected(new Set(paged.map(r => r.id)))
  }

  const toggleRule = (rule) => {
    saveRule({ ...rule, enabled: !rule.enabled })
  }

  const toggleAllRules = (enable) => {
    if (confirm(`确定${enable ? '启用' : '禁用'}所有规则？`)) {
      const updated = rules.map(r => ({ ...r, enabled: enable }))
      persist(updated)
    }
  }

  const exportCSV = () => {
    const header = 'Name,Enabled,Mode,ProbePath,MatchScope,MatchStatusCode,MatchCondition,MatchType,Pattern,PassiveScope'
    const rows = rules.map(r =>
      [r.name, r.enabled ? '1' : '0', r.probePath ? 'active' : 'passive',
       r.probePath || '', r.matchScope || '', r.matchStatusCode || '',
       r.matchCondition || '', r.matchType || 'contains', r.pattern, r.scope || 'url']
      .map(v => `"${String(v).replace(/"/g, '""')}"`)
      .join(',')
    )
    const csv = [header, ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'rules.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const importCSV = (e) => {
    const file = e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const lines = ev.target.result.split('\n').filter(Boolean)
      const imported = lines.slice(1).map((line, i) => {
        const cols = line.split(',').map(c => c.replace(/^"|"$/g, '').replace(/""/g, '"'))
        return {
          id: Date.now() + i,
          name: cols[0] || '',
          enabled: cols[1] !== '0',
          probePath: cols[3] || '',
          matchScope: cols[4] || '',
          matchStatusCode: cols[5] || '',
          matchCondition: cols[6] || '',
          matchType: cols[7] || 'contains',
          pattern: cols[8] || '',
          scope: cols[9] || 'url',
        }
      }).filter(r => r.name && r.pattern)
      persist([...rules, ...imported])
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const filtered = rules.filter(r => {
    const t = search.toLowerCase()
    return r.name.toLowerCase().includes(t) || r.pattern.toLowerCase().includes(t) ||
      (r.probePath || '').toLowerCase().includes(t)
  })

  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  return (
    <div className="tab-content">
      {editing && <RuleModal rule={editing} onSave={saveRule} onCancel={() => setEditing(null)} />}
      {fpOpen && <FpImportModal onImport={(newRules) => persist([...rules, ...newRules])} onCancel={() => setFpOpen(false)} />}
      <div className="toolbar">
        <input className="search-input" placeholder="搜索名称、模式、路径..." value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }} />
        {selected.size > 0
          ? <button className="icon-btn danger" onClick={bulkDelete}>删除({selected.size})</button>
          : <>
              <button className="icon-btn" onClick={() => toggleAllRules(true)}>全部启用</button>
              <button className="icon-btn" onClick={() => toggleAllRules(false)}>全部禁用</button>
              <button className="icon-btn" onClick={exportCSV}>导出</button>
              <label className="icon-btn" style={{cursor:'pointer'}}>
                导入<input ref={importRef} type="file" accept=".csv" style={{display:'none'}} onChange={importCSV} />
              </label>
              <button className="icon-btn" onClick={() => setFpOpen(true)}>指纹导入</button>
            </>
        }
        <button className="icon-btn primary" onClick={() => setEditing({ id: null, name: '', enabled: true, scope: 'url', matchType: 'contains', pattern: '', probePath: '', action: 'alert' })}>
          + 新建
        </button>
      </div>
      {paged.length === 0
        ? <div className="empty-state"><div className="empty-icon">📋</div><p>{search ? '无匹配规则' : '暂无规则'}</p><small>点击「新建」添加规则</small></div>
        : paged.map(rule => (
          <div key={rule.id} className={`rule-item ${selected.has(rule.id) ? 'selected' : ''}`}>
            <input type="checkbox" className="rule-checkbox" checked={selected.has(rule.id)} onChange={() => toggleSelect(rule.id)} />
            <span className={`rule-status-dot ${rule.enabled ? 'on' : 'off'}`} title={rule.enabled ? '点击禁用' : '点击启用'} onClick={() => toggleRule(rule)} />
            <div className="rule-info">
              <div className="rule-name">{rule.name}</div>
              <div className="rule-meta">
                <span className={`rule-tag ${rule.probePath ? 'active' : 'passive'}`}>{rule.probePath ? 'Active' : 'Passive'}</span>
                {rule.probePath
                  ? <span className="rule-pattern">{rule.probePath}</span>
                  : <span className="rule-pattern">{rule.scope || 'url'} · "{rule.pattern}"</span>
                }
                {rule.matchStatusCode && <span className="rule-tag passive">HTTP {rule.matchStatusCode}</span>}
              </div>
            </div>
            <div className="rule-actions">
              <button className="icon-btn" onClick={() => setEditing(rule)}>编辑</button>
              <button className="icon-btn danger" onClick={() => deleteRule(rule.id)}>删除</button>
            </div>
          </div>
        ))
      }
      {(totalPages > 1 || paged.length > 0) && (
        <div className="pagination">
          {paged.length > 0 && (
            <label className="page-select-all">
              <input type="checkbox" checked={paged.length > 0 && selected.size === paged.length} onChange={toggleSelectAll} />
              <span>全选</span>
            </label>
          )}
          {totalPages > 1 && <>
            <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}>上一页</button>
            <span className="page-info">{page} / {totalPages}</span>
            <button className="page-btn" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>下一页</button>
          </>}
        </div>
      )}
    </div>
  )
}

// ── Logs Tab ──────────────────────────────────────────────────────────────────
function LogsTab() {
  const [logs, setLogs] = useState([])
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const PER_PAGE = 10

  useEffect(() => {
    loadLogs()
    const t = setInterval(loadLogs, 3000)
    return () => clearInterval(t)
  }, [])

  const loadLogs = () => {
    chrome.storage.local.get('logs', d => setLogs(d.logs || []))
  }

  const clearLogs = () => {
    if (confirm('确定清空所有日志？')) {
      chrome.storage.local.set({ logs: [] }, () => setLogs([]))
    }
  }

  const exportLogs = () => {
    const headers = ['时间', '规则', 'URL', '类型', '信息']
    const rows = [...logs].reverse().map(log => [
      new Date(log.timestamp).toLocaleString(),
      `"${(log.ruleName || '').replace(/"/g, '""')}"`,
      `"${(log.url || '').replace(/"/g, '""')}"`,
      log.type || '',
      `"${(log.message || '').replace(/"/g, '""')}"`
    ].join(','))
    const csv = '\uFEFF' + [headers.join(','), ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nothing_hits_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // 最新优先
  const filtered = [...logs].reverse().filter(l => {
    const t = search.toLowerCase()
    return (l.ruleName || '').toLowerCase().includes(t) || (l.url || '').toLowerCase().includes(t)
  })

  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const typeClass = (type) => {
    if (!type) return 'info'
    if (type === 'match') return 'match'
    if (type === 'warn' || type === 'warning') return 'warn'
    if (type === 'error') return 'error'
    return 'info'
  }

  return (
    <div className="tab-content">
      <div className="toolbar">
        <input className="search-input" placeholder="搜索命中日志..." value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }} />
        <button className="icon-btn" onClick={exportLogs}>导出</button>
        <button className="icon-btn" onClick={loadLogs}>刷新</button>
        <button className="icon-btn danger" onClick={clearLogs}>清空</button>
      </div>
      {paged.length === 0
        ? <div className="empty-state"><div className="empty-icon">📄</div><p>暂无命中日志</p><small>规则匹配后自动记录</small></div>
        : paged.map((log, i) => (
          <div key={i} className="log-item">
            <span className="log-time">{new Date(log.timestamp).toLocaleString()}</span>
            <span className={`log-type-tag ${typeClass(log.type)}`}>{log.type || 'info'}</span>
            <div className="log-body">
              <div className="log-rule">{log.ruleName || '—'}</div>
              <div className="log-url" title={log.url}>{log.url}</div>
            </div>
            <button className="copy-btn-sm" onClick={() => navigator.clipboard.writeText(log.url || '')} title="复制 URL">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        ))
      }
      {totalPages > 1 && (
        <div className="pagination">
          <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}>上一页</button>
          <span className="page-info">{page} / {totalPages}</span>
          <button className="page-btn" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>下一页</button>
        </div>
      )}
    </div>
  )
}

// ── Settings Tab ──────────────────────────────────────────────────────────────
function SettingsTab() {
  const [settings, setSettings] = useState({})
  const [saved, setSaved] = useState(false)
  const [jsonInput, setJsonInput] = useState('')
  const [jsonError, setJsonError] = useState('')
  const [showJson, setShowJson] = useState(false)
  const jsonRef = useRef(null)

  useEffect(() => {
    chrome.runtime.sendMessage({ action: 'GET_SETTINGS' }, (res) => {
      setSettings(res?.settings || {})
    })
  }, [])

  const toggle = (key, currentOn) => {
    const newVal = currentOn === undefined ? !settings[key] : !currentOn
    setSettings(s => ({ ...s, [key]: newVal }))
    chrome.runtime.sendMessage({ action: 'SET_SETTING', key, value: newVal })
  }

  const setField = (key, value) => {
    setSettings(s => ({ ...s, [key]: value }))
  }

  const saveAI = () => {
    if (!settings.aiKey) { setJsonError('API Key 不能为空'); return }
    setJsonError('')
    const values = {
      aiProvider: settings.aiProvider || 'openai',
      aiKey: settings.aiKey,
      aiModel: settings.aiModel || '',
      aiEndpoint: settings.aiEndpoint || ''
    }
    chrome.runtime.sendMessage({ action: 'SET_SETTINGS_BULK', values }, () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    })
  }

  // Parse various JSON config formats
  const importFromJson = () => {
    setJsonError('')
    let raw = jsonInput.trim()
    if (!raw) { setJsonError('请粘贴 JSON 配置'); return }
    try {
      const obj = JSON.parse(raw)
      const env = obj.env || obj
      const extracted = {}

      if (env.ANTHROPIC_AUTH_TOKEN || env.ANTHROPIC_API_KEY) {
        extracted.aiProvider = 'anthropic'
        extracted.aiKey = env.ANTHROPIC_AUTH_TOKEN || env.ANTHROPIC_API_KEY
        extracted.aiEndpoint = env.ANTHROPIC_BASE_URL || ''
        extracted.aiModel = env.ANTHROPIC_MODEL || env.ANTHROPIC_DEFAULT_SONNET_MODEL || env.ANTHROPIC_DEFAULT_HAIKU_MODEL || ''
      } else if (env.DEEPSEEK_API_KEY) {
        extracted.aiProvider = 'deepseek'
        extracted.aiKey = env.DEEPSEEK_API_KEY
        extracted.aiEndpoint = env.DEEPSEEK_BASE_URL || ''
        extracted.aiModel = env.DEEPSEEK_MODEL || ''
      } else if (env.GLM_API_KEY || env.ZHIPU_API_KEY || env.ZHIPUAI_API_KEY) {
        extracted.aiProvider = 'glm'
        extracted.aiKey = env.GLM_API_KEY || env.ZHIPU_API_KEY || env.ZHIPUAI_API_KEY
        extracted.aiEndpoint = env.GLM_BASE_URL || env.ZHIPU_BASE_URL || ''
        extracted.aiModel = env.GLM_MODEL || env.ZHIPU_MODEL || ''
      } else if (env.OPENAI_API_KEY) {
        extracted.aiProvider = 'openai'
        extracted.aiKey = env.OPENAI_API_KEY
        extracted.aiEndpoint = env.OPENAI_BASE_URL || ''
        extracted.aiModel = env.OPENAI_MODEL || ''
      } else if (env.apiKey || env.api_key) {
        extracted.aiProvider = 'custom'
        extracted.aiKey = env.apiKey || env.api_key
        extracted.aiEndpoint = env.baseUrl || env.base_url || env.endpoint || ''
        extracted.aiModel = env.model || ''
      } else {
        setJsonError('未识别格式，支持 ANTHROPIC_AUTH_TOKEN / OPENAI_API_KEY / DEEPSEEK_API_KEY / GLM_API_KEY / apiKey')
        return
      }

      if (!extracted.aiKey) { setJsonError('未找到 API Key 字段'); return }

      // Single atomic write — no race condition
      chrome.runtime.sendMessage({ action: 'SET_SETTINGS_BULK', values: extracted }, () => {
        setSettings(s => ({ ...s, ...extracted }))
        setJsonInput('')
        setShowJson(false)
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
      })
    } catch (e) {
      setJsonError('JSON 解析失败: ' + e.message)
    }
  }

  const TOGGLES = [
    { key: 'activeScan', label: '主动扫描', desc: '主动探测配置的路径规则（也用于 XSS 参数探针）' },
    { key: 'backupScan', label: '备份文件扫描', desc: '扫描备份文件、版本控制泄露等敏感文件' },
    { key: 'dynamicScan', label: '动态扫描', desc: '监听 SPA 页面动态内容变化' },
    { key: 'deepScan', label: '深度扫描', desc: '获取并扫描外部 JS 文件内容' },
    { key: 'aiAnalysis', label: 'AI 分析', desc: '自动使用 AI 过滤误报和分析漏洞（消耗 token）' },
    { key: 'pocVerify', label: 'POC 主动验证', desc: '后台自动加载 XSS POC 实测是否弹窗，只保留真正能打的（会短暂打开后台标签触发 payload）', defaultOn: true },
  ]

  const provider = settings.aiProvider || 'openai'
  const providerCfg = getProvider(provider)
  const placeholderModel = providerCfg.modelPlaceholder || providerCfg.defaultModel || 'gpt-4o-mini'
  const placeholderKey = providerCfg.keyPlaceholder || 'sk-...'
  const showEndpoint = providerCfg.allowProxy

  return (
    <div className="tab-content">
      <div className="setting-section-title">扫描设置</div>
      {TOGGLES.map(({ key, label, desc, defaultOn }) => {
        const on = defaultOn ? settings[key] !== false : !!settings[key]
        return (
        <div key={key} className="setting-row">
          <div className="setting-info">
            <div className="setting-label">{label}</div>
            <div className="setting-desc">{desc}</div>
          </div>
          <button className={`toggle ${on ? 'on' : 'off'}`} onClick={() => toggle(key, on)}>
            <span className="toggle-knob"></span>
          </button>
        </div>
        )})}

      <div className="setting-section-title">AI 配置</div>

      {/* JSON import */}
      <div className="setting-field">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <label className="setting-field-label">JSON 导入</label>
          <button className="icon-btn" style={{ padding: '2px 8px', fontSize: '0.65rem' }}
            onClick={() => { setShowJson(v => !v); setJsonError('') }}>
            {showJson ? '收起' : '粘贴 JSON 配置'}
          </button>
        </div>
        {showJson && (
          <>
            <textarea
              ref={jsonRef}
              className="setting-input"
              style={{ height: 90, resize: 'vertical', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
              placeholder={'{\n  "env": {\n    "ANTHROPIC_AUTH_TOKEN": "sk-ant-...",\n    "ANTHROPIC_BASE_URL": "https://..."\n  }\n}'}
              value={jsonInput}
              onChange={e => setJsonInput(e.target.value)}
            />
            <button className="load-btn" style={{ alignSelf: 'flex-start', padding: '5px 14px', fontSize: '0.75rem', marginTop: 4 }}
              onClick={importFromJson}>
              解析并导入
            </button>
          </>
        )}
        {jsonError && <div className="ai-error" style={{ marginTop: 4 }}>{jsonError}</div>}
      </div>

      <div className="setting-row">
        <div className="setting-info"><div className="setting-label">服务商</div></div>
        <select className="setting-select" value={provider} onChange={e => setField('aiProvider', e.target.value)}>
          {Object.entries(AI_PROVIDERS).map(([id, cfg]) => (
            <option key={id} value={id}>{cfg.label}</option>
          ))}
        </select>
      </div>
      <div className="setting-field">
        <label className="setting-field-label">API Key</label>
        <input className="setting-input" type="password" placeholder={placeholderKey}
          value={settings.aiKey || ''} onChange={e => setField('aiKey', e.target.value)} />
      </div>
      <div className="setting-field">
        <label className="setting-field-label">模型</label>
        <input className="setting-input" type="text" placeholder={placeholderModel}
          value={settings.aiModel || ''} onChange={e => setField('aiModel', e.target.value)} />
      </div>
      {showEndpoint && (
        <div className="setting-field">
          <label className="setting-field-label">
            {providerCfg.proxyRequired ? '自定义端点' : '代理地址 (留空用官方)'}
          </label>
          <input className="setting-input" type="text"
            placeholder={providerCfg.proxyRequired ? 'https://your-proxy.com' : (providerCfg.base || 'https://your-proxy.com')}
            value={settings.aiEndpoint || ''} onChange={e => setField('aiEndpoint', e.target.value)} />
        </div>
      )}
      <button className="load-btn" style={{ alignSelf: 'flex-start', padding: '6px 18px', fontSize: '0.78rem' }} onClick={saveAI}>
        {saved ? '✓ 已保存' : '保存配置'}
      </button>
    </div>
  )
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState('scan')

  return (
    <div className="popup-root">
      <header className="popup-header">
        <div className="popup-logo">
          <div className="popup-logo-icon">N</div>
          <span className="popup-title">Nothing</span>
        </div>
        <span className="status-dot" title="运行中"></span>
        <nav className="popup-tabs">
          {TABS.map(t => (
            <button key={t.id} className={`tab-btn ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <div className="popup-body">
        {activeTab === 'scan' && <ScanTab />}
        {activeTab === 'backup' && <BackupTab />}
        {activeTab === 'fingerprint' && <FingerprintTab />}
        {activeTab === 'site' && <SiteTab />}
        {activeTab === 'rules' && <RulesTab />}
        {activeTab === 'logs' && <LogsTab />}
        {activeTab === 'exclusion' && <ExclusionTab />}
        {activeTab === 'settings' && <SettingsTab />}
      </div>
    </div>
  )
}
// ── Exclusion Modal ───────────────────────────────────────────────────────────
function ExclusionModal({ item, onSave, onCancel }) {
  const [value, setValue] = useState(item?.value || '')

  const handleSave = () => {
    if (!value.trim()) { alert('请填写规则内容'); return }
    onSave({ ...item, id: item?.id || Date.now(), value: value.trim() })
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onCancel()}>
      <div className="modal-box">
        <div className="modal-title">{item?.id ? '编辑规则' : '新建规则'}</div>
        <div className="modal-field">
          <label className="modal-label">域名 / IP 规则</label>
          <input className="modal-input" placeholder="e.g. *.example.com or 192.168.1.0/24"
            value={value} onChange={e => setValue(e.target.value)} />
        </div>
        <div className="modal-actions">
          <button className="modal-cancel" onClick={onCancel}>取消</button>
          <button className="modal-save" onClick={handleSave}>保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Exclusion Tab ─────────────────────────────────────────────────────────────
function ExclusionTab() {
  const [subTab, setSubTab] = useState('exclusions')
  const [items, setItems] = useState([])
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState(null)
  const [page, setPage] = useState(1)
  const importRef = useRef(null)
  const PER_PAGE = 8

  useEffect(() => {
    chrome.storage.local.get(subTab, d => {
      const raw = d[subTab] || []
      // migrate legacy string arrays to {id, value} objects
      setItems(raw.map((i, idx) => typeof i === 'string' ? { id: Date.now() + idx, value: i } : i))
    })
    setPage(1)
  }, [subTab])

  const persist = (newItems) => {
    chrome.storage.local.set({ [subTab]: newItems }, () => setItems(newItems))
  }

  const saveItem = (item) => {
    const idx = items.findIndex(i => i.id === item.id)
    const next = idx >= 0 ? items.map((i, n) => n === idx ? item : i) : [...items, item]
    persist(next)
    setEditing(null)
  }

  const deleteItem = (id) => {
    if (confirm('确定删除此规则？')) persist(items.filter(i => i.id !== id))
  }

  const exportCSV = () => {
    const csv = ['Rule', ...items.map(i => `"${i.value.replace(/"/g, '""')}"`)]
      .join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `${subTab}.csv`; a.click()
    URL.revokeObjectURL(url)
  }

  const importCSV = (e) => {
    const file = e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const lines = ev.target.result.split('\n').filter(Boolean)
      const imported = lines.slice(1).map((line, i) => ({
        id: Date.now() + i,
        value: line.replace(/^"|"$/g, '').replace(/""/g, '"').trim()
      })).filter(i => i.value)
      persist([...items, ...imported])
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const filtered = items.filter(i => i.value.toLowerCase().includes(search.toLowerCase()))
  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  return (
    <div className="tab-content">
      {editing !== null && <ExclusionModal item={editing} onSave={saveItem} onCancel={() => setEditing(null)} />}
      <div className="excl-subtabs">
        <button className={`excl-subtab ${subTab === 'exclusions' ? 'active' : ''}`} onClick={() => setSubTab('exclusions')}>全局排除</button>
        <button className={`excl-subtab ${subTab === 'customWhitelist' ? 'active' : ''}`} onClick={() => setSubTab('customWhitelist')}>内容白名单</button>
      </div>
      <div className="toolbar">
        <input className="search-input" placeholder="搜索规则..." value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }} />
        <button className="icon-btn" onClick={exportCSV}>导出</button>
        <label className="icon-btn" style={{cursor:'pointer'}}>
          导入
          <input ref={importRef} type="file" accept=".csv" style={{display:'none'}} onChange={importCSV} />
        </label>
        <button className="icon-btn primary" onClick={() => setEditing({})}>+ 新建</button>
      </div>
      {paged.length === 0
        ? <div className="empty-state"><div className="empty-icon">🚫</div><p>暂无规则</p><small>点击「新建」添加排除规则</small></div>
        : paged.map(item => (
          <div key={item.id} className="excl-item">
            <span className="excl-type-icon">◈</span>
            <span className="excl-value">{item.value}</span>
            <div className="rule-actions">
              <button className="icon-btn" onClick={() => setEditing(item)}>编辑</button>
              <button className="icon-btn danger" onClick={() => deleteItem(item.id)}>删除</button>
            </div>
          </div>
        ))
      }
      {totalPages > 1 && (
        <div className="pagination">
          <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}>上一页</button>
          <span className="page-info">{page} / {totalPages}</span>
          <button className="page-btn" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>下一页</button>
        </div>
      )}
    </div>
  )
}