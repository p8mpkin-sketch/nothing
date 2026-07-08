import React from 'react';

export function UsageGuide() {
    return (
        <div className="usage-guide">
            <div className="guide-section">
                <h3>🚀 快速开始 (Quick Start)</h3>
                <p>
                    <strong>Nothing</strong> 是一款强大的被动监测与主动探测工具。它可以帮助您在浏览网页时自动发现敏感信息，或主动探测隐藏的 API 端点。
                </p>
            </div>

            <div className="guide-section">
                <h3>🛡️ 规则引擎 (Rule Engine)</h3>
                <div className="subsection">
                    <h4>1. 被动监测 (Passive Monitoring)</h4>
                    <p>在您正常浏览网页时，插件会自动检查流量。</p>
                    <ul>
                        <li><strong>URL 路径</strong>: 检查 URL 是否包含敏感词 (如 <code>admin</code>, <code>config</code>)。</li>
                        <li><strong>HTTP 头</strong>: 检查响应头 (如 <code>Set-Cookie</code>, <code>Server</code>)。</li>
                        <li><strong>响应体</strong>: 检查页面内容 (如 <code>API Key</code>, <code>手机号</code>)。</li>
                    </ul>
                </div>

                <div className="subsection">
                    <h4>2. 主动探测 (Active Probing)</h4>
                    <p>针对当前访问的域名，主动发送请求探测隐藏路径。</p>
                    <ul>
                        <li><strong>探测路径</strong>: 支持多路径匹配 (正则语法)。
                            <ul>
                                <li>例如: <code>/actuator/|/actuator/env</code> 会同时探测两个路径。</li>
                                <li>留空则探测当前 URL。</li>
                            </ul>
                        </li>
                        <li><strong>智能去重</strong>: 插件会自动识别目录层级，忽略 <code>.ico</code>, <code>.jpg</code> 等静态文件，且对同一域名下的相同路径只探测一次，避免重复请求。</li>
                        <li><strong>状态码匹配</strong>: 指定期望的状态码 (如 <code>200, 403</code>)。</li>
                        <li><strong>空内容匹配</strong>: 若要匹配空响应体，请选择 "Regex" 模式并输入 <code>^$</code>。</li>
                    </ul>
                </div>
            </div>

            <div className="guide-section">
                <h3>📊 规则管理 (Management)</h3>
                <ul>
                    <li><strong>搜索与筛选</strong>: 支持通过名称、匹配模式或探测路径搜索规则。</li>
                    <li><strong>批量操作</strong>: 支持多选规则进行批量删除。</li>
                    <li><strong>分页显示</strong>: 规则列表每页显示 10 条，方便管理大量规则。</li>
                    <li><strong>排除设置 (Exclus)</strong>: 点击 "排除设置" 按钮，配置要忽略的域名或 IP 段。
                        <ul>
                            <li>支持通配符: <code>*.google.com</code> (匹配所有 google.com 子域名)</li>
                            <li>支持 CIDR: <code>192.168.0.0/24</code> (匹配该网段内所有 IP)</li>
                            <li>支持搜索、分页和批量删除排除规则。</li>
                            <li>支持导入/导出排除规则 (CSV/XLS)。</li>
                        </ul>
                    </li>
                    <li><strong>导入/导出</strong>: 支持 CSV 格式的规则导入导出，方便备份和分享。</li>
                    <li><strong>启用/禁用</strong>: 点击规则左侧的圆点 ● 可快速切换规则状态。</li>
                </ul>
            </div>

            <div className="guide-section">
                <h3>📝 活动日志 (Activity Logs)</h3>
                <ul>
                    <li><strong>实时记录</strong>: 所有命中的规则都会记录在此。</li>
                    <li><strong>搜索日志</strong>: 支持通过规则名称、URL 或详细信息搜索日志。</li>
                    <li><strong>批量管理</strong>: 支持多选删除日志，或一键清空所有日志。</li>
                    <li><strong>导出 Excel</strong>: 将日志导出为 CSV 文件进行分析。</li>
                    <li><strong>通知</strong>: 命中规则时会播放提示音并弹出系统通知。</li>
                </ul>
            </div>
        </div>
    );
}
