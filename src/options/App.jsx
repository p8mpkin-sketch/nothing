import React, { useState, useEffect } from "react"
import "./index.css"
import { RuleEditor } from "./RuleEditor";
import { LogViewer } from "./LogViewer";
import { ExclusionManager } from "./ExclusionManager";

function App() {
    const [activeTab, setActiveTab] = useState("rules");
    const [rules, setRules] = useState([]);

    useEffect(() => { loadRules(); }, []);

    const loadRules = () => {
        chrome.storage.local.get("rules", (data) => {
            setRules(data.rules || []);
        });
    };

    const saveRule = (rule) => {
        const existingIndex = rules.findIndex(r => r.id === rule.id);
        let newRules;
        if (existingIndex >= 0) {
            newRules = [...rules];
            newRules[existingIndex] = rule;
        } else {
            newRules = [...rules, rule];
        }
        chrome.storage.local.set({ rules: newRules }, () => setRules(newRules));
    };

    const deleteRule = (id) => {
        const newRules = rules.filter(r => r.id !== id);
        chrome.storage.local.set({ rules: newRules }, () => setRules(newRules));
    };

    const importRules = (newRulesList) => {
        const updatedRules = [...rules, ...newRulesList];
        chrome.storage.local.set({ rules: updatedRules }, () => setRules(updatedRules));
    };

    return (
        <div className="app-container">
            <aside className="sidebar">
                <div className="brand">
                    <div className="logo-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <h1>Nothing</h1>
                </div>
                <nav>
                    <button className={"nav-item " + (activeTab === "rules" ? "active" : "")} onClick={() => setActiveTab("rules")}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                        规则引擎
                    </button>
                    <button className={"nav-item " + (activeTab === "exclusions" ? "active" : "")} onClick={() => setActiveTab("exclusions")}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                        排除 / 白名单
                    </button>
                    <button className={"nav-item " + (activeTab === "logs" ? "active" : "")} onClick={() => setActiveTab("logs")}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                        命中日志
                    </button>
                </nav>
            </aside>
            <main className="main-content">
                <header className="top-bar">
                    <h2>
                        {activeTab === "rules" && "规则配置"}
                        {activeTab === "exclusions" && "排除 / 白名单"}
                        {activeTab === "logs" && "命中日志"}
                    </h2>
                </header>
                <div className="content-area">
                    {activeTab === "rules" && (
                        <div className="fade-in">
                            <div className="card">
                                <div className="card-header">
                                    <h3>规则管理</h3>
                                    <p className="hint-text">配置被动监测或主动探测规则。</p>
                                </div>
                                <RuleEditor rules={rules} onSave={saveRule} onDelete={deleteRule} onImport={importRules} />
                            </div>
                        </div>
                    )}
                    {activeTab === "exclusions" && (
                        <div className="fade-in">
                            <div className="card">
                                <ExclusionManager />
                            </div>
                        </div>
                    )}
                    {activeTab === "logs" && (
                        <div className="fade-in">
                            <div className="card">
                                <LogViewer />
                            </div>
                        </div>
                    )}
                </div>
            </main>
        </div>
    )
}

export default App
