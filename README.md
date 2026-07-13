# Nothing

> You Can Do Everything !

Nothing 是一个 Chrome 浏览器扩展（Manifest V3），浏览网页时自动收集页面里的敏感信息、识别技术栈指纹，结合静态检测和 AI 做 XSS 漏洞发现、WAF 绕过 POC 生成和主动验证。

AI 和规则引擎是两条主线：AI 负责过滤误报和研判漏洞上下文（支持 OpenAI / Anthropic / DeepSeek / 智谱 GLM，AI 不可用时切回静态检测），规则引擎负责主动发包探测 + 指纹命中告警（支持粘贴 xray/afrog 风格 CEL 表达式一键导入）。

[![Version](https://img.shields.io/badge/version-1.6.0-blue)](https://github.com/p8mpkin-sketch/nothing)
[![Manifest](https://img.shields.io/badge/manifest-v3-green)](https://developer.chrome.com/docs/extensions/mv3/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

---

## 功能

**信息采集**
- 20+ 正则分类器，覆盖 API、凭据密钥（30+ 种格式）、内网 IP、邮箱、手机号、路径等
- Webpack chunk map 解析，递归抓懒加载 JS，提升 SPA 接口覆盖率
- Vue Router 嵌套路由重建，拼完整前端路由
- 降噪：API 按查询参数键去重、IP 禁前导零、文档文件过滤裸配置名

**主动探测与指纹**
- 自定义路径 + 匹配条件主动发包，支持递归深度
- 粘贴 CEL 表达式指纹一键转探测规则
- 响应头 / Cookie / HTML 多维提取技术栈，覆盖 Spring Boot、Jenkins、GitLab、Kong 等 30+ 框架
- declarativeNetRequest 会话规则注入 Cookie，绕过 fetch 限制
- [`rules_example.csv`](rules_example.csv) 提供规则引擎的简单样例，覆盖 Actuator、Druid、Nacos、Shiro 等常见中间件指纹探测，可直接参考或导入使用

**XSS 检测与 POC 验证**
- 静态检测覆盖 HTML 标签注入、属性注入、JS 字符串注入、DOM XSS、过滤绕过
- WAF 绕过：unicode 混淆关键字 + tagged template 免括号 + 上下文自动闭合
- 后台标签实测每条 POC，弹窗才保留，不弹/被拦直接扔，具备自纠正

**AI**
- 扫描结果二次清洗去噪
- 提取 JS source/sink 代码块交大模型分析漏洞
- 支持 OpenAI、Anthropic、DeepSeek、智谱 GLM、自定义服务商
- AI 不可用时自动降级

**备份文件扫描**
- 探测 .git / .svn / .env / 压缩包等敏感路径，AI 二次过滤排除 404/错误页

---

## 快速开始

```bash
git clone https://github.com/p8mpkin-sketch/nothing.git
cd nothing
npm install
npm run build
```

Chrome 打开 `chrome://extensions/` → 开发者模式 → 加载已解压的扩展程序 → 选 `dist/` 目录。

打开任意网页点扩展栏的 N 图标即开始扫描。结果分高危/中危/低危三级，支持搜索、复制全部。

---

## 架构

```
┌──────────────────────────────────────────┐
│  UI 层（popup + options）                 │
│  React 组件，通过 chrome.runtime.send-    │
│  Message 和 background 通信               │
├──────────────────────────────────────────┤
│  Content Script 层（页面注入）            │
│  DOM 扫描、参数采集、内联脚本片段提取、    │
│  Webpack / Vue Router 解析                │
├──────────────────────────────────────────┤
│  Background 层（Service Worker）          │
│  消息路由、AI 调用、规则引擎、主动扫描、   │
│  XSS 检测、POC 验证、指纹识别             │
├──────────────────────────────────────────┤
│  Storage 层                               │
│  chrome.storage.local（持久化）+           │
│  chrome.storage.session（会话级缓存）      │
└──────────────────────────────────────────┘
```

### 项目结构

```
nothing-plugin/
├── public/
│   ├── manifest.json          # 扩展声明
│   └── poc-hook.js            # POC 验证 MAIN world hook
├── src/
│   ├── background/            # Service Worker
│   │   ├── index.js           # 主入口
│   │   ├── scanner.js         # 主动扫描
│   │   ├── ruleEngine.js      # 规则引擎
│   │   ├── staticXssDetector.js  # 静态 XSS 检测
│   │   ├── pocVerifier.js     # POC 主动验证
│   │   ├── fingerprint.js     # 技术指纹
│   │   ├── networkMonitor.js  # 网络监听
│   │   ├── backupScanner.js   # 备份扫描
│   │   ├── siteAnalysis.js    # ICP/IP 查询
│   │   ├── probeRegistry.js   # 探针注册
│   │   └── urlParser.js       # URL 解析
│   ├── content/               # Content Script
│   │   ├── index.js
│   │   ├── scanner.config.js  # 分类器正则
│   │   └── scanner.filter.js
│   ├── popup/                 # 弹出窗口（主 UI）
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── options/               # 选项页
│   │   ├── App.jsx
│   │   ├── RuleEditor.jsx
│   │   ├── ExclusionManager.jsx
│   │   ├── LogViewer.jsx
│   │   └── UsageGuide.jsx
│   └── utils/
│       ├── aiProviders.js     # AI 服务商注册
│       ├── exclusionMatcher.js
│       └── fingerprintImporter.js  # CEL 解析导入
└── vite.config.js
```

---

## 版本更新

### V1.6.1 — 2026-07-13
- 修复：图标文件实际为 JPEG 伪装 PNG，导致 Chrome 清单校验失败
- 新增：浏览器工具栏图标（icon.png）
- 发布 CRX 打包格式，可直接拖入 Chrome 安装

### V1.6.0 — 2026-07-08
大版本：POC 引擎重写 + AI WAF 绕过 + 误报三层过滤
- 独立 POC 引擎（pocEngine.js）：上下文解析器识别反射点中的引号类型、对象/数组/模板、编码方式、框架自动转义
- 12 种 WAF 绕过策略（unicode 混淆、tagged template、base64、charcode、注释拆分、大小写、onfocus 替代 onerror 等）
- 验证三态结果：弹窗 ✓、WAF 拦截 🛡️、误报 ✂️（误报直接删除不显示）
- WAF 拦截时自动触发 AI 生成自定义绕过 POC 并重试（需配置 AI Key）
- WAF 策略管理器分数持久化到 chrome.storage（跨 SW 重启保留）
- 两段式 AI：有反射证据时只发 snippet（~200 tokens），无反射才发 JS 深度分析

### V1.5.0 — 2026-07-01
大版本：XSS POC 主动验证
- 后台标签逐条加载候选 POC，实测是否弹窗
- document_start 注入 MAIN world alert hook，不真弹、不卡后台
- 只保留实测触发的 POC，不弹/被拦直接丢弃
- 自纠正：上下文猜错也能把能弹的 POC 提为主推，置信度 98%

### V1.4.0 — 2026-05-01
大版本：XSS 检测质量优化
- 修复属性注入子串碰撞误报（`www` 命中 href）
- 按 type+source+sink 去重
- WAF 感知 POC：unicode 混淆 + tagged template + 对象闭合
- 主 POC 一条，附两条兜底，不堆模板

### V1.3.2 — 2026-03-15
- 降噪：文档文件正则要求路径含 `/`，移除 csv/conf/ini/yml/yaml

### V1.3.1 — 2026-03-01
- 修复 IP 误报：禁前导零，只留内网 IP

### V1.3.0 — 2026-02-15
大版本：吸收被动提取广度
- Webpack 分块枚举（单页上限 150 个 JS）
- Vue Router 嵌套路由提取
- API 按查询参数键去重
- 密钥模式扩充（Anthropic/OpenAI/Slack/SendGrid 等）
- JS 抓取兜底：executeScript 带 cookie 回退

<details>
<summary>更早版本</summary>

### V1.2.7 — 2026-01-20
- 分类新增「复制全部」、新增「文档文件」分类

### V1.2.6 — 2026-01-05
- 修复 SW 回收导致去重缓存丢失

### V1.2.5 — 2025-12-20
- 修复 ICP 备案查询，新增站点信息条

### V1.2.4 — 2025-12-05
- 整站指纹同域名只报一次

### V1.2.3 — 2025-11-20
- 修复 Cookie/Set-Cookie 探测无法命中

### V1.2.2 — 2025-11-08
- CEL 表达式指纹导入

### V1.2.1 — 2025-10-25
- 新增 DeepSeek、智谱 GLM 支持

### V1.2.0 — 2025-10-10 基线
- 扫描、AI 分析、规则引擎、备份扫描、动态/深度扫描

</details>

小优化 patch 递增，大功能 minor 递增。
