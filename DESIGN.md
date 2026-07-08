# Nothing 架构设计

## 整体结构

Nothing 是一个 Chrome 扩展（Manifest V3），四层架构：

```
┌──────────────────────────────────────────┐
│  UI 层（popup + options）                 │
│  React 组件，通过 chrome.runtime.send-    │
│  Message 和 background 通信               │
├──────────────────────────────────────────┤
│  Content Script 层（页面注入）            │
│  每个页面跑一份，做 DOM 扫描、参数采集、   │
│  内联脚本片段提取，结果发回 background    │
├──────────────────────────────────────────┤
│  Background 层（Service Worker）          │
│  核心调度：消息路由、AI 调用、规则引擎、  │
│  主动扫描、XSS 检测、POC 验证、指纹识别  │
├──────────────────────────────────────────┤
│  Storage 层                               │
│  chrome.storage.local（持久化：设置、规则、│
│  排除项、指纹）、chrome.storage.session    │
│  （会话级：去重缓存、扫描结果）           │
└──────────────────────────────────────────┘
```

## 数据流

### 扫描流程

```
用户打开页面
    │
    ▼
Content Script 注入（document_idle）
    │── DOM 全文正则扫描（20+ 分类器）
    │── 页面参数采集（URL query params）
    │── 内联脚本片段提取（参数值反射检测）
    │── Webpack chunk map 解析
    │── Vue Router 路由提取
    │
    ▼ chrome.runtime.sendMessage("SCAN_RESULTS")
Background 收到结果
    │── 存入 tabScanResults[tabId]
    │── 触发 AI 误报过滤（防抖 3s）
    │── 触发漏洞分析 + 静态 XSS 检测（防抖 4s）
    │── 触发主动探测规则（如果开启 activeScan）
    │
    ▼
Popup 轮询（每 3s 调 GET_SCAN_RESULTS / GET_VULN_RESULTS / GET_AI_STATUS）
    │── 展示结果
```

### AI 过滤流程

```
autoAiFilter(tabId)
    │
    ├─ 没配 AI key 或关了 AI 分析 → 跳过，用原始结果
    │
    ├─ 收集 scanData 各分类数据
    ├─ 截断（每类最多 80 条，每条最多 200 字符）
    ├─ callAI(..., 'filter')
    │     ├─ provider=openai → /v1/chat/completions
    │     └─ provider=anthropic → /v1/messages
    ├─ 解析返回的 JSON
    ├─ 合并回 tabScanResults → tabFilteredResults[tabId]
    └─ 更新 tabAiStatus[tabId].filter
```

### 漏洞分析流程（静态 + AI 双路径）

```
autoAnalyzeVulns(tabId, pageUrl)
    │
    ├─ 1. 静态检测（始终执行）
    │     staticXssDetector.analyze(scanData, pageUrl)
    │     产出: HTML标签注入 / 属性注入 / JS字符串注入 / DOM XSS / 过滤绕过
    │
    ├─ 2. AI 分析（如果配了 key 且开了 AI）
    │     ├─ 收集 JS 文件内容（优先同源、短文件，最多 5 个）
    │     ├─ 智能提取 source/sink 代码块（大文件裁剪）
    │     ├─ 参数反射探针（标记 marker 主动探测）
    │     ├─ callAI(..., 'xss')
    │     └─ enrichReflectedXssPocs() 后处理
    │
    ├─ 3. 合并结果（mergeVulnResults）
    │     按 type+source+sink 指纹去重
    │
    ├─ 4. POC 主动验证（verifyAndBadge）← V1.5.0 新增
    │     ├─ 后台标签逐条加载 POC URL
    │     ├─ document_start 注入 alert hook
    │     └─ 读取弹窗标志，只保留实测触发的 POC
    │
    └─ 5. 存入 tabVulnResults[tabId]，更新徽标
```

### POC 主动验证流程

```
verifyXssFindings(vulns)
    │
    ├─ 筛选：只测含 "xss" 的漏洞类型 + 有有效 GET URL 的 POC
    ├─ 确定目标 origin → registerContentScripts(poc-hook.js, MAIN world)
    ├─ 创建隐藏标签（about:blank）
    │
    └─ 逐条 POC 循环：
          ├─ tabs.update(url = POC)
          ├─ 等页面 complete（最多 6s）
          ├─ scripting.executeScript(MAIN world) 读 window.__NOTHING_POC_FIRED__
          ├─ fired=true → 标记 verified，break（该漏洞够了）
          └─ fired=false → 继续下一条
    │
    ├─ verified.length > 0 → v.pocs = verified（只留能打的）
    ├─ verified.length = 0 → 保留原候选
    ├─ v.confidence = 0.98（实测级别）
    │
    └─ 注销 hook → 关闭标签
```

## 关键模块说明

### staticXssDetector.js — 静态 XSS 检测

不依赖 AI，纯正则 + 上下文分析。五种检测路径：

| 检测类型 | 判断逻辑 | 误报控制 |
|---------|---------|---------|
| HTML 标签注入 | 值反射到 body.innerHTML 或危险 sink 附近 | 要求值含 `<` 标签头或命中 HTML 反射证据 |
| 属性注入 | 值出现在 href/src/action 等属性中 | **值必须在属性取值开头**（子串碰撞排除） |
| JS 字符串注入 | 值在 `"..."` 或 `'...'` 字符串字面量里 | 区分对象上下文 vs 普通字符串，给不同闭合 POC |
| DOM XSS | source（location.*）→ sink（innerHTML 等） | 要求 source 和 sink 同时出现在同一 snippet |
| 过滤绕过 | 关键字被过滤但 snippet 里不出现 | 自动生成大小写/unicode/实体编码绕过 |

### pocVerifier.js — POC 主动验证

核心思路：别猜了，直接跑一遍看弹不弹。

- 用 `chrome.scripting.registerContentScripts` 在 `document_start` 注入 MAIN world hook
- hook 把 `alert/confirm/prompt` 替换为写 `window.__NOTHING_POC_FIRED__ = true`
- 不会真弹窗，后台标签不会卡住
- 用完立即 `unregisterContentScripts`，不留全局注入
- 验证后置信度直接拉满到 0.98

### ruleEngine.js — 规则引擎

- 规则结构：`{ path, method, matchHeaders, matchBody, statusCode, hostDedupe }`
- 匹配去重：`persistentMatchCache`（规则+URL，30 分钟 TTL）+ `matchedRuleHosts`（整站指纹按域名）
- 缓存持久化到 `chrome.storage.session`，跨 SW 重启保留
- Cookie 注入：通过 `declarativeNetRequest` 会话规则，绕过 fetch 的 forbidden header 限制

### aiProviders.js — 多服务商适配

统一管理各 AI 服务商的差异：

- `baseUrl` + `chatPath` → 拼接完整请求地址
- `protocol` → 决定请求体格式（OpenAI 兼容 vs Anthropic Messages）
- `buildBody` → 构造请求体
- `headers` → 认证头
- `JSON_IMPORT_KEY_MAP` → JSON 导入时自动识别环境变量名

新增服务商只需往 `PROVIDERS` 加一个对象。

## 存储设计

| Key | 位置 | 内容 | 生命周期 |
|-----|------|------|---------|
| `settings` | chrome.storage.local | 用户设置（AI key/开关等） | 持久 |
| `rules` | chrome.storage.local | 规则引擎规则列表 | 持久 |
| `fingerprints` | chrome.storage.local | 技术栈指纹 | 持久 |
| `exclusions` | chrome.storage.local | 排除项列表 | 持久 |
| `persistentMatchCache` | chrome.storage.session | 规则匹配去重缓存 | 浏览器关闭清 |
| `matchedRuleHosts` | chrome.storage.session | 整站指纹去重 | 浏览器关闭清 |
| `tabScanResults` | 内存（Map） | 当前标签的扫描结果 | SW 重启丢失 |
| `tabVulnResults` | 内存（Map） | 当前标签的漏洞结果 | SW 重启丢失 |
| `tabAiStatus` | 内存（Map） | AI 分析状态 | SW 重启丢失 |

`tabScanResults` 等内存状态在 SW 重启后会丢失，但 popup 每 3s 轮询时会重新触发扫描——content script 会再次注入并发回 SCAN_RESULTS。

## 权限说明

```
"scripting"          → POC 验证注入 MAIN world hook、JS 抓取兜底
"declarativeNetRequest" → Cookie 注入（绕过 fetch 限制）
"webRequest"         → 监听响应头（Set-Cookie 匹配）
"tabs"               → 后台标签管理
"activeTab"          → 当前标签操作
"storage"            → 设置/规则/缓存持久化
"notifications"      → 高危漏洞桌面通知
"offscreen"          → 音频播放
"<all_urls>"         → 任意页面注入 content script
```
