import React, { useState, useEffect } from 'react';

export function LogViewer() {
    const [logs, setLogs] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [selectedIndices, setSelectedIndices] = useState(new Set());
    const itemsPerPage = 10;

    useEffect(() => {
        loadLogs();
        // Poll for new logs every 2 seconds
        const interval = setInterval(loadLogs, 2000);
        return () => clearInterval(interval);
    }, []);

    // Reset selection when logs change (or maybe keep it? better reset to avoid index mismatch)
    useEffect(() => {
        setSelectedIndices(new Set());
    }, [logs, searchTerm]);

    const loadLogs = () => {
        chrome.storage.local.get('logs', (data) => {
            setLogs(data.logs || []);
        });
    };

    const clearLogs = () => {
        if (confirm('确定要清空所有日志吗？')) {
            chrome.storage.local.set({ logs: [] }, () => {
                setLogs([]);
            });
        }
    };

    const handleBulkDelete = () => {
        if (confirm(`确定要删除选中的 ${selectedIndices.size} 条日志吗？`)) {
            // We need to filter out logs that are in the selectedIndices relative to the *current view*? 
            // Actually, indices are tricky with pagination and search.
            // Better to use timestamps or some unique ID. Logs currently don't have unique IDs guaranteed.
            // Let's assume timestamp + url + ruleName is unique enough, or just filter by index from the *original* list?
            // Since we are paginating a filtered list, mapping back to original indices is hard.
            // STRATEGY: Add a temporary ID to logs when loading if they don't have one, or just filter based on content equality?
            // Best approach: Add ID to logs in backend. But I can't easily change backend right now.
            // Workaround: Filter the *original* logs array. 
            // To do this safely, I need to know which logs in the *original* array correspond to the selected ones.
            // Let's use the object reference since `logs` is the source of truth.

            const logsToDelete = new Set([...selectedIndices].map(idx => paginatedLogs[idx])); // These are the actual log objects
            const newLogs = logs.filter(log => !logsToDelete.has(log));

            chrome.storage.local.set({ logs: newLogs }, () => {
                setLogs(newLogs);
                setSelectedIndices(new Set());
            });
        }
    };

    const refreshLogs = () => {
        loadLogs();
    };

    const exportToExcel = () => {
        const headers = ['Time', 'Rule', 'URL', 'Type', 'Info'];
        const csvContent = [
            headers.join(','),
            ...logs.map(log => {
                const row = [
                    new Date(log.timestamp).toLocaleString(),
                    `"${(log.ruleName || '').replace(/"/g, '""')}"`,
                    `"${(log.url || '').replace(/"/g, '""')}"`,
                    log.type,
                    `"${(log.message || '').replace(/"/g, '""')}"`
                ];
                return row.join(',');
            })
        ].join('\n');

        const blob = new Blob([`\uFEFF${csvContent}`], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `nothing_logs_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
    };

    // Filter Logic — 最新优先
    const filteredLogs = [...logs].reverse().filter(log => {
        const term = searchTerm.toLowerCase();
        return (
            (log.ruleName && log.ruleName.toLowerCase().includes(term)) ||
            (log.url && log.url.toLowerCase().includes(term)) ||
            (log.message && log.message.toLowerCase().includes(term))
        );
    });

    // Pagination Logic
    const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);
    const paginatedLogs = filteredLogs.slice(
        (currentPage - 1) * itemsPerPage,
        currentPage * itemsPerPage
    );

    // Selection Logic
    // We use the index *within the paginated view* for selection state to keep it simple for the UI
    // But for deletion, we mapped back to the object.
    const toggleSelectAll = () => {
        if (selectedIndices.size === paginatedLogs.length && paginatedLogs.length > 0) {
            setSelectedIndices(new Set());
        } else {
            const newSelected = new Set();
            paginatedLogs.forEach((_, idx) => newSelected.add(idx));
            setSelectedIndices(newSelected);
        }
    };

    const toggleSelect = (index) => {
        const newSelected = new Set(selectedIndices);
        if (newSelected.has(index)) {
            newSelected.delete(index);
        } else {
            newSelected.add(index);
        }
        setSelectedIndices(newSelected);
    };

    const handleImportLogs = (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const content = e.target.result;
                let importedLogs = [];

                if (file.name.endsWith('.json')) {
                    importedLogs = JSON.parse(content);
                } else {
                    // Assume CSV
                    const lines = content.split('\n');
                    // Skip header
                    for (let i = 1; i < lines.length; i++) {
                        if (!lines[i].trim()) continue;
                        // Simple CSV parse - matches exportToExcel format
                        // Note: This is a basic parser and might fail on complex CSVs with newlines in fields
                        // But for logs it should be okay-ish. 
                        // Let's use the same robust parser as in RuleEditor if possible, or a simplified one.
                        // Format: Time, Rule, URL, Type, Info
                        // We need to reconstruct the object.
                        // Actually, JSON is much better for "extracting from default record file".
                        // I will encourage JSON for backup/restore.
                        // But let's try to parse CSV too.

                        // Regex to match CSV fields with quotes
                        const matches = lines[i].match(/(".*?"|[^",\s]+)(?=\s*,|\s*$)/g);
                        // This regex is too simple.
                        // Let's just support JSON for reliable import/export of logs, 
                        // and keep CSV for "Export to Excel" (viewing).
                        // If user wants to "extract from default record file", JSON is the way.
                        // I will add a "Export JSON" button too.
                    }
                    if (importedLogs.length === 0) {
                        // If CSV parsing not implemented fully, warn user.
                        // Or just try to parse JSON.
                        try {
                            importedLogs = JSON.parse(content);
                        } catch (e) {
                            alert('目前仅支持导入 JSON 格式的日志备份文件。请使用 "备份日志 (JSON)" 功能导出的文件。');
                            return;
                        }
                    }
                }

                if (!Array.isArray(importedLogs)) {
                    alert('文件格式错误：应为日志数组。');
                    return;
                }

                // Merge logs (avoid duplicates based on timestamp + url + ruleName?)
                // Or just append? User might want to see history.
                // Let's append and let them clear if needed.
                // Actually, let's try to deduplicate exact matches.
                const existingSignatures = new Set(logs.map(l => `${l.timestamp}|${l.url}|${l.ruleName}`));
                const newLogs = importedLogs.filter(l => !existingSignatures.has(`${l.timestamp}|${l.url}|${l.ruleName}`));

                if (newLogs.length === 0) {
                    alert('未发现新日志 (所有日志已存在)。');
                    return;
                }

                const updatedLogs = [...logs, ...newLogs].sort((a, b) => b.timestamp - a.timestamp).slice(-500); // Keep last 500? Or more? Logger keeps 100.
                // Logger.js keeps 100. Let's increase limit here or respect it?
                // If we import, we might want to see more.
                // Let's save to storage.

                chrome.storage.local.set({ logs: updatedLogs }, () => {
                    setLogs(updatedLogs);
                    alert(`成功导入 ${newLogs.length} 条日志。`);
                });

            } catch (err) {
                console.error('Import failed:', err);
                alert('导入失败，请检查文件格式。');
            }
        };
        reader.readAsText(file);
    };

    const exportToJson = () => {
        const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `nothing_logs_backup_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="log-viewer">
            <div className="header" style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginBottom: '15px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3>命中日志</h3>
                    <div className="actions" style={{ display: 'flex', gap: '10px' }}>
                        <button onClick={exportToJson}>备份日志 (JSON)</button>
                        <label className="button">
                            导入日志
                            <input type="file" accept=".json" onChange={handleImportLogs} style={{ display: 'none' }} />
                        </label>
                        <button onClick={exportToExcel}>导出 Excel</button>
                        <button onClick={loadLogs}>刷新</button>
                        <button className="danger" onClick={clearLogs}>清空所有</button>
                    </div>
                </div>

                <div className="toolbar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)', padding: '10px', borderRadius: '8px' }}>
                    <input
                        type="text"
                        placeholder="搜索日志..."
                        value={searchTerm}
                        onChange={e => setSearchTerm(e.target.value)}
                        style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', width: '300px' }}
                    />
                    {selectedIndices.size > 0 && (
                        <button className="danger" onClick={handleBulkDelete}>
                            删除选中 ({selectedIndices.size})
                        </button>
                    )}
                </div>
            </div>

            <div className="log-list">
                {filteredLogs.length === 0 ? (
                    <div className="empty-logs" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>暂无匹配记录</div>
                ) : (
                    <>
                        <div className="list-header" style={{ display: 'flex', padding: '10px 15px', borderBottom: '1px solid var(--border-color)', fontWeight: 500, color: 'var(--text-secondary)' }}>
                            <div style={{ width: '30px' }}>
                                <input
                                    type="checkbox"
                                    checked={paginatedLogs.length > 0 && selectedIndices.size === paginatedLogs.length}
                                    onChange={toggleSelectAll}
                                />
                            </div>
                            <div style={{ flex: 1 }}>日志详情</div>
                        </div>

                        {paginatedLogs.map((log, index) => (
                            <div key={index} className={`log-item ${log.type}`} style={{ display: 'flex', alignItems: 'center', paddingLeft: '15px' }}>
                                <div style={{ width: '30px', marginRight: '10px' }}>
                                    <input
                                        type="checkbox"
                                        checked={selectedIndices.has(index)}
                                        onChange={() => toggleSelect(index)}
                                    />
                                </div>
                                <div style={{ flex: 1, display: 'grid', gridTemplateColumns: 'auto auto 150px 1fr 1fr auto', gap: '10px', alignItems: 'center' }}>
                                    <span className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                                    <span className={`log-tag ${log.type}`}>{log.type.toUpperCase()}</span>
                                    <span className="log-rule" title={`Rule: ${log.ruleName}`}>{log.ruleName}</span>
                                    <span className="log-url" title={log.url}>{log.url}</span>
                                    <span className="log-message" title={log.message} style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{log.message}</span>
                                    <button
                                        className="copy-btn"
                                        onClick={() => copyToClipboard(log.url)}
                                        title="复制 URL"
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        ))}

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
            </div>
        </div>
    );
}
