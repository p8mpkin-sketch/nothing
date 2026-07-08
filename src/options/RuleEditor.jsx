import React, { useState, useEffect } from 'react';
import { parseFingerprints } from '../utils/fingerprintImporter';

const FP_PLACEHOLDER = `header_contains_with_cookie:
  request:
    method: GET
    path: /
    headers:
      Cookie: rememberMe=true
  expression: response.raw_header.bcontains(b'=deleteMe') || response.raw_header.bcontains(b'shiro-cas')`;

// Import rules written in the CEL-expression fingerprint format (xray/afrog style).
function FingerprintModal({ onImport, onCancel }) {
    const [text, setText] = useState('');
    const [namePrefix, setNamePrefix] = useState('');
    const [result, setResult] = useState(null); // { rules, warnings, errors }

    const handleParse = () => {
        if (!text.trim()) { setResult({ rules: [], warnings: [], errors: ['请粘贴指纹内容'] }); return; }
        setResult(parseFingerprints(text, { namePrefix: namePrefix.trim() }));
    };

    const handleConfirm = () => {
        if (!result || result.rules.length === 0) return;
        const withIds = result.rules.map((r, i) => ({ ...r, id: Date.now() + i }));
        onImport(withIds);
        alert(`成功导入 ${withIds.length} 条指纹规则！`);
        onCancel();
    };

    return (
        <div className="modal">
            <div className="header-row">
                <h3>指纹格式导入 (Fingerprint Import)</h3>
            </div>
            <small style={{ color: 'var(--text-secondary)', display: 'block', marginBottom: '12px' }}>
                粘贴 CEL 表达式指纹(xray / afrog 风格),自动转换为主动探测规则。支持 <code>&&</code> / <code>||</code> /
                括号嵌套、<code>contains</code>/<code>bcontains</code>、<code>raw_header</code>/<code>body</code> 及状态码。可一次粘贴多个。
            </small>

            <div className="form-group">
                <label>名称前缀 (可选)</label>
                <input
                    placeholder="例如: shiro (留空则用指纹自身的键名)"
                    value={namePrefix}
                    onChange={e => setNamePrefix(e.target.value)}
                />
            </div>

            <div className="form-group">
                <label>指纹内容 (YAML)</label>
                <textarea
                    style={{ width: '100%', height: '220px', fontFamily: 'monospace', fontSize: '0.82rem', resize: 'vertical' }}
                    placeholder={FP_PLACEHOLDER}
                    value={text}
                    onChange={e => { setText(e.target.value); setResult(null); }}
                />
            </div>

            {result && (
                <div style={{ marginBottom: '15px' }}>
                    {result.errors.length > 0 && (
                        <div style={{ color: 'var(--danger-color)', fontSize: '0.85rem', marginBottom: '6px' }}>
                            {result.errors.map((e, i) => <div key={i}>✕ {e}</div>)}
                        </div>
                    )}
                    {result.rules.length > 0 && (
                        <div style={{ background: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px' }}>
                            <div style={{ fontWeight: 500, marginBottom: '6px' }}>解析成功 {result.rules.length} 条:</div>
                            {result.rules.map((r, i) => (
                                <div key={i} style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                                    • {r.name} — <span style={{ color: '#4ade80' }}>Active {r.probePath}</span>{' '}
                                    [{r.matchScope === 'response_header' ? '响应头' : '响应体'} / {r.matchType}]
                                </div>
                            ))}
                        </div>
                    )}
                    {result.warnings.length > 0 && (
                        <div style={{ color: '#d97706', fontSize: '0.8rem', marginTop: '8px' }}>
                            {result.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
                        </div>
                    )}
                </div>
            )}

            <div className="actions">
                <button onClick={onCancel}>取消</button>
                {result && result.rules.length > 0
                    ? <button className="primary" onClick={handleConfirm}>确认导入 {result.rules.length} 条</button>
                    : <button className="primary" onClick={handleParse}>解析预览</button>}
            </div>
        </div>
    );
}

function RuleModal({ rule, onSave, onCancel }) {
    const [editingRule, setEditingRule] = useState(rule);
    // Initialize mode based on the passed rule
    const [mode, setMode] = useState(rule.probePath ? 'active' : 'passive');

    // Parse initial headers
    const parseHeaders = (str) => {
        if (!str) return [{ key: '', value: '' }];
        const parsed = str.split('\n').map(line => {
            const parts = line.split(':');
            if (parts.length < 2) return null;
            return { key: parts[0].trim(), value: parts.slice(1).join(':').trim() };
        }).filter(Boolean);
        return parsed.length > 0 ? parsed : [{ key: '', value: '' }];
    };

    const [headersList, setHeadersList] = useState(() => parseHeaders(rule.requestHeaders));

    // Sync headersList to editingRule.requestHeaders whenever it changes
    useEffect(() => {
        const headerString = headersList
            .filter(h => h.key && h.value)
            .map(h => `${h.key}: ${h.value}`)
            .join('\n');
        setEditingRule(prev => ({ ...prev, requestHeaders: headerString }));
    }, [headersList]);

    const handleModeChange = (newMode) => {
        setMode(newMode);
        if (newMode === 'passive') {
            setEditingRule({ ...editingRule, probePath: '', requestHeaders: '', matchScope: 'url' });
        } else {
            setEditingRule({ ...editingRule, probePath: editingRule.probePath || '/', matchScope: 'body' });
        }
    };

    const handleSave = () => {
        if (!editingRule.name || !editingRule.pattern) {
            alert('请填写规则名称和匹配内容');
            return;
        }
        // If probePath is set, scope is implicitly 'body' (response text) or 'response_header'
        if (editingRule.probePath && !editingRule.matchScope) {
            editingRule.matchScope = 'body';
        }
        onSave(editingRule);
    };

    const updateHeader = (index, field, value) => {
        const newList = [...headersList];
        newList[index][field] = value;
        setHeadersList(newList);
    };

    const addHeader = () => {
        setHeadersList([...headersList, { key: '', value: '' }]);
    };

    const removeHeader = (index) => {
        const newList = headersList.filter((_, i) => i !== index);
        setHeadersList(newList.length ? newList : [{ key: '', value: '' }]);
    };

    return (
        <div className="modal">
            <div className="header-row">
                <h3>{editingRule.id ? '编辑规则' : '新建规则'}</h3>
            </div>

            <div className="form-group">
                <label>规则名称 (Rule Name)</label>
                <input
                    placeholder="例如: 探测 Actuator 端点"
                    value={editingRule.name}
                    onChange={e => setEditingRule({ ...editingRule, name: e.target.value })}
                />
            </div>

            {/* Mode Toggle */}
            <div className="form-group">
                <label>检测模式 (Rule Mode)</label>
                <div className="mode-toggle" style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                    <button
                        className={mode === 'passive' ? 'primary' : ''}
                        onClick={() => handleModeChange('passive')}
                        style={{ flex: 1, opacity: mode === 'passive' ? 1 : 0.6 }}
                    >
                        被动监测 (Passive)
                    </button>
                    <button
                        className={mode === 'active' ? 'primary' : ''}
                        onClick={() => handleModeChange('active')}
                        style={{ flex: 1, opacity: mode === 'active' ? 1 : 0.6 }}
                    >
                        主动探测 (Active)
                    </button>
                </div>
                <small style={{ color: 'var(--text-secondary)' }}>
                    {mode === 'passive'
                        ? "被动监测: 在您浏览网页时自动检查流量。适用于发现 URL 或页面内容中的敏感信息。"
                        : "主动探测: 主动向特定路径发送请求。适用于发现隐藏文件或漏洞 (如 /actuator/, /admin)。"}
                </small>
            </div>

            {mode === 'active' && (
                <div style={{ background: 'var(--bg-color)', padding: '15px', borderRadius: '8px', border: '1px solid var(--border-color)', marginBottom: '20px' }}>
                    <div className="form-group">
                        <label>探测路径 (Path to Probe)</label>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>Current Origin + </span>
                            <input
                                style={{ flex: 1, fontFamily: 'monospace' }}
                                placeholder="/actuator/"
                                value={editingRule.probePath || ''}
                                onChange={e => setEditingRule({ ...editingRule, probePath: e.target.value })}
                            />
                        </div>
                        <small style={{ color: 'var(--text-secondary)', marginTop: '5px', display: 'block' }}>
                            留空则探测当前页面 URL。
                        </small>
                    </div>

                    <div className="form-group">
                        <label>请求头 (Request Headers)</label>
                        <div className="headers-editor" style={{ background: '#fff', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px' }}>
                            {headersList.map((header, index) => (
                                <div key={index} style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                                    <input
                                        placeholder="Key (e.g. Cookie)"
                                        value={header.key}
                                        onChange={e => updateHeader(index, 'key', e.target.value)}
                                        style={{ flex: 1, fontFamily: 'monospace', fontSize: '0.85rem' }}
                                    />
                                    <input
                                        placeholder="Value (e.g. rememberMe=del)"
                                        value={header.value}
                                        onChange={e => updateHeader(index, 'value', e.target.value)}
                                        style={{ flex: 2, fontFamily: 'monospace', fontSize: '0.85rem' }}
                                    />
                                    <button
                                        onClick={() => removeHeader(index)}
                                        style={{ padding: '0 10px', background: 'transparent', color: 'var(--danger-color)', border: '1px solid var(--border-color)' }}
                                        title="删除"
                                    >
                                        ✕
                                    </button>
                                </div>
                            ))}
                            <button
                                onClick={addHeader}
                                style={{ width: '100%', padding: '8px', border: '1px dashed var(--border-color)', background: 'transparent', color: 'var(--text-secondary)', cursor: 'pointer' }}
                            >
                                + 添加请求头
                            </button>
                        </div>
                    </div>

                    <div className="form-group">
                        <label>匹配范围 (Match Scope)</label>
                        <select
                            value={editingRule.matchScope || 'body'}
                            onChange={e => setEditingRule({ ...editingRule, matchScope: e.target.value })}
                        >
                            <option value="body">响应体 (Response Body)</option>
                            <option value="response_header">响应头 (Response Headers)</option>
                        </select>
                    </div>

                    <div className="form-row" style={{ display: 'flex', gap: '20px' }}>
                        <div className="form-group" style={{ flex: 1 }}>
                            <label>状态码匹配 (Status Code)</label>
                            <input
                                placeholder="e.g. 200, 403 (Leave empty to ignore)"
                                value={editingRule.matchStatusCode || ''}
                                onChange={e => setEditingRule({ ...editingRule, matchStatusCode: e.target.value })}
                            />
                        </div>
                        <div className="form-group" style={{ flex: 1 }}>
                            <label>匹配逻辑 (Logic)</label>
                            <select
                                value={editingRule.matchCondition || 'and'}
                                onChange={e => setEditingRule({ ...editingRule, matchCondition: e.target.value })}
                                disabled={!editingRule.matchStatusCode}
                            >
                                <option value="and">AND (状态码 + 内容)</option>
                                <option value="or">OR (状态码 或 内容)</option>
                            </select>
                        </div>
                    </div>
                </div>
            )}

            {mode === 'passive' && (
                <div className="form-group">
                    <label>检查范围 (Look In)</label>
                    <select
                        value={editingRule.scope}
                        onChange={e => setEditingRule({ ...editingRule, scope: e.target.value })}
                    >
                        <option value="url">URL 路径</option>
                        <option value="header">HTTP 头 (Headers)</option>
                        <option value="body">响应体 (Response Body)</option>
                    </select>
                </div>
            )
            }

            <div className="form-row" style={{ display: 'flex', gap: '20px' }}>
                <div className="form-group" style={{ flex: 1 }}>
                    <label>匹配方式 (Match Method)</label>
                    <select
                        value={editingRule.matchType}
                        onChange={e => setEditingRule({ ...editingRule, matchType: e.target.value })}
                    >
                        <option value="contains">包含文本 (Contains)</option>
                        <option value="regex">正则表达式 (Regex)</option>
                    </select>
                </div>
            </div>

            <div className="form-group">
                <label>匹配内容 (Matching Pattern)</label>
                <input
                    placeholder={editingRule.matchType === 'regex' ? '^.*' : '输入要查找的文本'}
                    value={editingRule.pattern}
                    onChange={e => setEditingRule({ ...editingRule, pattern: e.target.value })}
                />
            </div>

            <div className="actions">
                <button onClick={onCancel}>取消</button>
                <button className="primary" onClick={handleSave}>保存规则</button>
            </div>
        </div >
    );
}

export function RuleEditor({ rules, onSave, onDelete, onImport }) {
    const [editingRule, setEditingRule] = useState(null);
    const [fpImporting, setFpImporting] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [selectedRules, setSelectedRules] = useState(new Set());
    const itemsPerPage = 10;

    // Reset selection and page when rules change or search changes
    useEffect(() => {
        setSelectedRules(new Set());
    }, [rules, searchTerm]);

    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm]);

    const handleAdd = () => {
        setEditingRule({
            id: null, // New rule
            name: '',
            enabled: true,
            scope: 'url',
            matchType: 'contains',
            pattern: '',
            probePath: '',
            action: 'alert',
            matchStatusCode: '',
            matchCondition: 'and'
        });
    };

    const handleSaveRule = (rule) => {
        // If it's a new rule (id is null), give it an ID
        const ruleToSave = { ...rule, id: rule.id || Date.now() };
        onSave(ruleToSave);
        setEditingRule(null);
    };

    const handleExport = () => {
        // Convert rules to CSV
        const headers = ['Name', 'Enabled', 'Mode', 'ProbePath', 'RequestHeaders', 'MatchScope', 'MatchStatusCode', 'MatchCondition', 'MatchType', 'Pattern', 'PassiveScope'];
        const csvContent = [
            headers.join(','),
            ...rules.map(r => {
                const mode = r.probePath ? 'active' : 'passive';
                // Helper to escape CSV fields: quote them, escape internal quotes, and escape newlines
                const escape = (val) => {
                    if (val === null || val === undefined) return '';
                    const str = String(val).replace(/\n/g, '\\n').replace(/"/g, '""');
                    return `"${str}"`;
                };

                const row = [
                    escape(r.name),
                    r.enabled,
                    mode,
                    escape(r.probePath),
                    escape(r.requestHeaders),
                    r.matchScope || '',
                    r.matchStatusCode || '',
                    r.matchCondition || 'and',
                    r.matchType,
                    escape(r.pattern),
                    r.scope || ''
                ];
                return row.join(',');
            })
        ].join('\n');

        const blob = new Blob([`\uFEFF${csvContent}`], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `nothing_rules_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const handleImport = (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const text = e.target.result;
                const lines = text.split('\n');

                // Robust CSV Line Parser
                const parseCSVLine = (line) => {
                    const result = [];
                    let current = '';
                    let inQuotes = false;

                    for (let i = 0; i < line.length; i++) {
                        const char = line[i];

                        if (char === '"') {
                            if (inQuotes && line[i + 1] === '"') {
                                // Escaped quote
                                current += '"';
                                i++;
                            } else {
                                // Toggle quote
                                inQuotes = !inQuotes;
                            }
                        } else if (char === ',' && !inQuotes) {
                            // End of field
                            result.push(current);
                            current = '';
                        } else {
                            current += char;
                        }
                    }
                    result.push(current);
                    return result;
                };

                const batchRules = [];
                let importedCount = 0;
                for (let i = 1; i < lines.length; i++) {
                    if (!lines[i].trim()) continue;
                    const row = parseCSVLine(lines[i]);
                    // We expect at least 11 columns, but some might be empty
                    if (row.length < 5) continue; // Basic validation

                    const [name, enabled, mode, probePath, requestHeaders, matchScope, matchStatusCode, matchCondition, matchType, pattern, passiveScope] = row;

                    // Helper to unescape
                    const unescape = (val) => val ? val.replace(/\\n/g, '\n') : '';

                    const newRule = {
                        id: Date.now() + i, // Ensure unique ID
                        name: unescape(name),
                        enabled: enabled === 'true',
                        probePath: mode === 'active' ? unescape(probePath) : '',
                        requestHeaders: unescape(requestHeaders),
                        matchScope: matchScope,
                        matchStatusCode: matchStatusCode,
                        matchCondition: matchCondition,
                        matchType: matchType,
                        pattern: unescape(pattern),
                        scope: passiveScope,
                        action: 'alert'
                    };
                    batchRules.push(newRule);
                    importedCount++;
                }

                if (batchRules.length > 0) {
                    onImport(batchRules);
                    alert(`成功导入 ${importedCount} 条规则！`);
                } else {
                    alert('未找到有效规则。');
                }
            } catch (err) {
                console.error('Import failed:', err);
                alert('导入失败，请检查文件格式。');
            }
        };
        reader.readAsText(file);
    };

    // Search Logic
    const filteredRules = rules.filter(rule => {
        const term = searchTerm.toLowerCase();
        return (
            rule.name.toLowerCase().includes(term) ||
            rule.pattern.toLowerCase().includes(term) ||
            (rule.probePath && rule.probePath.toLowerCase().includes(term))
        );
    });

    // Pagination Logic
    const totalPages = Math.ceil(filteredRules.length / itemsPerPage);
    const paginatedRules = filteredRules.slice(
        (currentPage - 1) * itemsPerPage,
        currentPage * itemsPerPage
    );

    // Selection Logic
    const toggleSelectAll = () => {
        if (selectedRules.size === paginatedRules.length && paginatedRules.length > 0) {
            setSelectedRules(new Set());
        } else {
            const newSelected = new Set();
            paginatedRules.forEach(r => newSelected.add(r.id));
            setSelectedRules(newSelected);
        }
    };

    const toggleSelect = (id) => {
        const newSelected = new Set(selectedRules);
        if (newSelected.has(id)) {
            newSelected.delete(id);
        } else {
            newSelected.add(id);
        }
        setSelectedRules(newSelected);
    };

    const handleBulkDelete = () => {
        if (confirm(`确定要删除选中的 ${selectedRules.size} 条规则吗？`)) {
            selectedRules.forEach(id => onDelete(id));
            setSelectedRules(new Set());
        }
    };

    if (editingRule) {
        return (
            <RuleModal
                rule={editingRule}
                onSave={handleSaveRule}
                onCancel={() => setEditingRule(null)}
            />
        );
    }

    if (fpImporting) {
        return (
            <FingerprintModal
                onImport={onImport}
                onCancel={() => setFpImporting(false)}
            />
        );
    }

    return (
        <div className="rule-list">
            <div className="header" style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginBottom: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3>已配置规则 (Configured Rules)</h3>
                    <div className="header-actions" style={{ display: 'flex', gap: '10px' }}>
                        <button onClick={handleExport}>导出规则</button>
                        <label className="button">
                            导入规则
                            <input type="file" accept=".csv,.xls,.xlsx" onChange={handleImport} style={{ display: 'none' }} />
                        </label>
                        <button onClick={() => setFpImporting(true)}>指纹格式导入</button>
                        <button className="primary" onClick={handleAdd}>+ 新建规则</button>
                    </div>
                </div>

                <div className="toolbar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)', padding: '10px', borderRadius: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
                        <input
                            type="text"
                            placeholder="搜索规则名称、内容..."
                            value={searchTerm}
                            onChange={e => setSearchTerm(e.target.value)}
                            style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', width: '300px' }}
                        />
                    </div>
                    {selectedRules.size > 0 && (
                        <button className="danger" onClick={handleBulkDelete}>
                            删除选中 ({selectedRules.size})
                        </button>
                    )}
                </div>
            </div>

            {filteredRules.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                    {searchTerm ? "没有找到匹配的规则。" : "暂无规则。请点击 \"+ 新建规则\" 开始配置。"}
                </div>
            ) : (
                <>
                    <div className="list-header" style={{ display: 'flex', padding: '10px 20px', borderBottom: '1px solid var(--border-color)', fontWeight: 500, color: 'var(--text-secondary)' }}>
                        <div style={{ width: '40px' }}>
                            <input
                                type="checkbox"
                                checked={paginatedRules.length > 0 && selectedRules.size === paginatedRules.length}
                                onChange={toggleSelectAll}
                            />
                        </div>
                        <div style={{ flex: 1 }}>规则详情</div>
                        <div style={{ width: '150px', textAlign: 'right' }}>操作</div>
                    </div>

                    <ul>
                        {paginatedRules.map(rule => {
                            const isProbe = !!rule.probePath;
                            return (
                                <li key={rule.id} className="rule-item" style={{ paddingLeft: '20px' }}>
                                    <div style={{ width: '40px', display: 'flex', alignItems: 'center' }}>
                                        <input
                                            type="checkbox"
                                            checked={selectedRules.has(rule.id)}
                                            onChange={() => toggleSelect(rule.id)}
                                        />
                                    </div>
                                    <div
                                        className={`status ${rule.enabled ? 'on' : 'off'}`}
                                        title={rule.enabled ? 'Enabled' : 'Disabled'}
                                        style={{ cursor: 'pointer', marginRight: '15px' }}
                                        onClick={() => onSave({ ...rule, enabled: !rule.enabled })}
                                    >
                                        ●
                                    </div>
                                    <div className="info">
                                        <span className="name">{rule.name}</span>
                                        <div className="meta">
                                            <span className={`tag ${isProbe ? 'active-tag' : 'passive-tag'}`} style={{
                                                background: isProbe ? 'rgba(34, 197, 94, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                                                color: isProbe ? '#4ade80' : '#60a5fa'
                                            }}>
                                                {isProbe ? `Active: ${rule.probePath}` : `Passive: ${rule.scope}`}
                                            </span>
                                            <span>{rule.matchType === 'regex' ? 'Regex' : 'Text'}: "{rule.pattern}"</span>
                                            {rule.matchStatusCode && (
                                                <span className="tag" style={{ background: '#f3f4f6', color: '#666' }}>
                                                    Status: {rule.matchStatusCode} ({rule.matchCondition?.toUpperCase()})
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    <div className="actions" style={{ margin: 0, display: 'flex', gap: '8px' }}>
                                        <button onClick={() => setEditingRule(rule)} className="button">Edit</button>
                                        <button onClick={() => onDelete(rule.id)} className="button danger">Delete</button>
                                    </div>
                                </li>
                            );
                        })}
                    </ul>

                    {totalPages > 1 && (
                        <div className="pagination" style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '20px', alignItems: 'center' }}>
                            <button
                                disabled={currentPage === 1}
                                onClick={() => setCurrentPage(p => p - 1)}
                                className="button"
                            >
                                上一页
                            </button>
                            <span style={{ color: 'var(--text-secondary)' }}>
                                {currentPage} / {totalPages}
                            </span>
                            <button
                                disabled={currentPage === totalPages}
                                onClick={() => setCurrentPage(p => p + 1)}
                                className="button"
                            >
                                下一页
                            </button>
                        </div>
                    )}
                </>
            )}
        </div >
    );
}
