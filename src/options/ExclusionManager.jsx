import React, { useState, useEffect } from 'react';

// Tab: exclusions (scan exclusions) or whitelist (content scan whitelist)
export function ExclusionManager() {
    const [tab, setTab] = useState('exclusions');
    const [exclusions, setExclusions] = useState([]);
    const [whitelist, setWhitelist] = useState([]);
    const [editingItem, setEditingItem] = useState(null);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [selectedIndices, setSelectedIndices] = useState(new Set());
    const itemsPerPage = 10;

    useEffect(() => { loadData(); }, []);
    useEffect(() => { setSelectedIndices(new Set()); setCurrentPage(1); }, [exclusions, whitelist, searchTerm, tab]);

    const loadData = () => {
        chrome.storage.local.get(['exclusions', 'customWhitelist'], (data) => {
            setExclusions(data.exclusions || []);
            setWhitelist(data.customWhitelist || []);
        });
    };

    const currentList = tab === 'exclusions' ? exclusions : whitelist;
    const storageKey = tab === 'exclusions' ? 'exclusions' : 'customWhitelist';
    const setCurrentList = tab === 'exclusions' ? setExclusions : setWhitelist;

    const saveList = (newList) => {
        chrome.storage.local.set({ [storageKey]: newList }, () => {
            setCurrentList(newList);
            setIsModalOpen(false);
            setEditingItem(null);
        });
    };

    const handleDelete = (index) => {
        if (confirm('确定要删除这条规则吗？')) {
            saveList(currentList.filter((_, i) => i !== index));
        }
    };

    const handleBulkDelete = () => {
        if (confirm(`确定要删除选中的 ${selectedIndices.size} 条规则吗？`)) {
            const itemsToDelete = new Set([...selectedIndices].map(idx => paginatedList[idx]));
            saveList(currentList.filter(item => !itemsToDelete.has(item)));
        }
    };

    const handleEdit = (index) => {
        setEditingItem({ index, value: currentList[index] });
        setIsModalOpen(true);
    };

    const handleAdd = () => { setEditingItem(null); setIsModalOpen(true); };

    const handleSaveItem = (value) => {
        if (!value.trim()) return;
        const newList = [...currentList];
        if (editingItem && editingItem.index !== undefined) {
            newList[editingItem.index] = value.trim();
        } else {
            newList.push(value.trim());
        }
        saveList(newList);
    };

    const handleExport = () => {
        const csvContent = ['Rule', ...currentList.map(item => `"${item.replace(/"/g, '""')}"`)] .join('\n');
        const blob = new Blob([`\uFEFF${csvContent}`], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `nothing_${tab}_${new Date().toISOString().slice(0, 10)}.csv`;
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
                const lines = e.target.result.split('\n');
                const startIdx = lines[0].toLowerCase().includes('rule') ? 1 : 0;
                const newItems = [];
                for (let i = startIdx; i < lines.length; i++) {
                    let line = lines[i].trim();
                    if (!line) continue;
                    if (line.startsWith('"') && line.endsWith('"')) line = line.slice(1, -1).replace(/""/g, '"');
                    if (line) newItems.push(line);
                }
                saveList([...new Set([...currentList, ...newItems])]);
                alert(`成功导入 ${newItems.length} 条规则！`);
            } catch (err) {
                alert('导入失败，请检查文件格式。');
            }
        };
        reader.readAsText(file);
    };

    const filteredList = currentList.filter(item => item.toLowerCase().includes(searchTerm.toLowerCase()));
    const totalPages = Math.ceil(filteredList.length / itemsPerPage);
    const paginatedList = filteredList.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

    const toggleSelectAll = () => {
        if (selectedIndices.size === paginatedList.length && paginatedList.length > 0) {
            setSelectedIndices(new Set());
        } else {
            setSelectedIndices(new Set(paginatedList.map((_, idx) => idx)));
        }
    };

    const toggleSelect = (index) => {
        const newSelected = new Set(selectedIndices);
        if (newSelected.has(index)) newSelected.delete(index); else newSelected.add(index);
        setSelectedIndices(newSelected);
    };

    const tabDesc = tab === 'exclusions'
        ? '配置不需要进行扫描或匹配的域名和 IP 地址。'
        : '配置内容扫描白名单，白名单内的域名不会被内容脚本扫描。';

    const addLabel = tab === 'exclusions' ? '新建排除规则' : '新建白名单规则';

    return (
        <div className="exclusion-manager">
            {/* Sub-tabs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '0' }}>
                {[{ id: 'exclusions', label: '全局排除' }, { id: 'whitelist', label: '内容白名单' }].map(t => (
                    <button
                        key={t.id}
                        onClick={() => setTab(t.id)}
                        style={{
                            padding: '8px 16px',
                            border: 'none',
                            background: 'transparent',
                            fontWeight: 600,
                            fontSize: '0.9rem',
                            cursor: 'pointer',
                            color: tab === t.id ? 'var(--accent-color)' : 'var(--text-secondary)',
                            borderBottom: tab === t.id ? '2px solid var(--accent-color)' : '2px solid transparent',
                            marginBottom: '-1px',
                        }}
                    >
                        {t.label}
                        <span style={{ marginLeft: '6px', background: 'var(--bg-secondary)', padding: '1px 6px', borderRadius: '10px', fontSize: '0.75rem' }}>
                            {t.id === 'exclusions' ? exclusions.length : whitelist.length}
                        </span>
                    </button>
                ))}
            </div>

            <div className="header" style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginBottom: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.875rem' }}>{tabDesc}</p>
                    <div className="header-actions" style={{ display: 'flex', gap: '10px' }}>
                        <button onClick={handleExport} className="button" style={{ padding: '8px 16px' }}>导出</button>
                        <label className="button" style={{ padding: '8px 16px', cursor: 'pointer' }}>
                            导入
                            <input type="file" accept=".csv,.txt" onChange={handleImport} style={{ display: 'none' }} />
                        </label>
                        <button className="primary" onClick={handleAdd} style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '8px 16px' }}>
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                            {addLabel}
                        </button>
                    </div>
                </div>
                <div className="toolbar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)', padding: '10px', borderRadius: '8px' }}>
                    <input
                        type="text"
                        placeholder="搜索规则..."
                        value={searchTerm}
                        onChange={e => setSearchTerm(e.target.value)}
                        style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', width: '300px', outline: 'none' }}
                        onFocus={e => e.target.style.borderColor = 'var(--primary-color)'}
                        onBlur={e => e.target.style.borderColor = 'var(--border-color)'}
                    />
                    {selectedIndices.size > 0 && (
                        <button className="danger" onClick={handleBulkDelete} style={{ padding: '8px 16px', borderRadius: '8px' }}>
                            删除选中 ({selectedIndices.size})
                        </button>
                    )}
                </div>
            </div>

            {filteredList.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', borderRadius: '12px', border: '1px dashed var(--border-color)' }}>
                    <p style={{ fontSize: '1rem' }}>{searchTerm ? '未找到匹配规则' : '暂无规则'}</p>
                    <p style={{ fontSize: '0.875rem', opacity: 0.8 }}>点击右上角按钮添加</p>
                </div>
            ) : (
                <div className="rule-list-container" style={{ background: 'var(--bg-secondary)', borderRadius: '12px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                    <div className="list-header" style={{ display: 'flex', padding: '10px 20px', borderBottom: '1px solid var(--border-color)', fontWeight: 500, color: 'var(--text-secondary)', background: '#fff' }}>
                        <div style={{ width: '40px' }}>
                            <input type="checkbox" checked={paginatedList.length > 0 && selectedIndices.size === paginatedList.length} onChange={toggleSelectAll} />
                        </div>
                        <div style={{ flex: 1 }}>规则</div>
                        <div style={{ width: '150px', textAlign: 'right' }}>操作</div>
                    </div>
                    {paginatedList.map((item, index) => (
                        <div key={item + index} className="rule-item" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: index === paginatedList.length - 1 ? 'none' : '1px solid var(--border-color)', background: 'white' }}>
                            <div style={{ width: '40px', display: 'flex', alignItems: 'center' }}>
                                <input type="checkbox" checked={selectedIndices.has(index)} onChange={() => toggleSelect(index)} />
                            </div>
                            <div className="info" style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
                                <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: item.includes('/') ? '#f3f4f6' : '#e0f2fe', color: item.includes('/') ? '#6b7280' : '#0284c7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                                </div>
                                <div>
                                    <div className="name" style={{ fontFamily: 'monospace', fontSize: '1rem', fontWeight: 500 }}>{item}</div>
                                    <div className="meta" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                                        {item.includes('/') ? 'CIDR IP Range' : 'Domain Wildcard'}
                                    </div>
                                </div>
                            </div>
                            <div className="actions" style={{ display: 'flex', gap: '8px' }}>
                                <button onClick={() => handleEdit(currentList.indexOf(item))} className="button" style={{ padding: '6px 12px', fontSize: '0.85rem' }}>编辑</button>
                                <button onClick={() => handleDelete(currentList.indexOf(item))} className="button danger" style={{ padding: '6px 12px', fontSize: '0.85rem' }}>删除</button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {totalPages > 1 && (
                <div className="pagination" style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '20px', alignItems: 'center' }}>
                    <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="button" style={{ padding: '8px 16px' }}>上一页</button>
                    <span style={{ color: 'var(--text-secondary)' }}>{currentPage} / {totalPages}</span>
                    <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="button" style={{ padding: '8px 16px' }}>下一页</button>
                </div>
            )}

            {isModalOpen && (
                <EditModal
                    initialValue={editingItem ? editingItem.value : ''}
                    title={tab === 'exclusions' ? (editingItem ? '编辑排除规则' : '新建排除规则') : (editingItem ? '编辑白名单规则' : '新建白名单规则')}
                    onSave={handleSaveItem}
                    onCancel={() => setIsModalOpen(false)}
                />
            )}
        </div>
    );
}

function EditModal({ initialValue, title, onSave, onCancel }) {
    const [value, setValue] = useState(initialValue);
    return (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="modal fade-in" style={{ width: '420px', background: 'white', borderRadius: '16px', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)', padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div>
                    <h3 style={{ margin: 0, fontSize: '1.25rem' }}>{title}</h3>
                    <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>输入域名或 IP 地址段。</p>
                </div>
                <div>
                    <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500, fontSize: '0.9rem' }}>规则内容</label>
                    <input
                        type="text"
                        value={value}
                        onChange={e => setValue(e.target.value)}
                        placeholder="e.g. *.google.com or 192.168.0.0/24"
                        autoFocus
                        style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-color)', fontSize: '1rem', fontFamily: 'monospace', outline: 'none' }}
                        onFocus={e => e.target.style.borderColor = 'var(--primary-color)'}
                        onBlur={e => e.target.style.borderColor = 'var(--border-color)'}
                        onKeyDown={e => e.key === 'Enter' && onSave(value)}
                    />
                    <div style={{ marginTop: '12px', fontSize: '0.85rem', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                        <strong>示例:</strong>
                        <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                            <li><code>*.example.com</code> - 匹配所有子域名</li>
                            <li><code>192.168.1.0/24</code> - 匹配局域网段</li>
                        </ul>
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                    <button onClick={onCancel} style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'white', cursor: 'pointer' }}>取消</button>
                    <button className="primary" onClick={() => onSave(value)} style={{ padding: '8px 20px', borderRadius: '8px' }}>保存</button>
                </div>
            </div>
        </div>
    );
}
