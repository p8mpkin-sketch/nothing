# Nothing

> You Can Do Everything !

**Nothing** 是一款 Chrome 浏览器扩展（Manifest V3），用于 Web 安全信息收集与漏洞辅助分析。

> ⚡ **两大核心驱动力：AI + 规则引擎**

- **🤖 AI 驱动**：接入大模型对扫描结果做智能研判——自动过滤误报、分析反射上下文、评估漏洞可利用性。支持 OpenAI / Anthropic / DeepSeek / 智谱 GLM / 自定义服务商，AI 不可用时自动降级为纯静态检测，不影响核心流程。
- **🎯 规则引擎**：自定义路径 + 匹配模式主动发包探测，命中即告警。支持 CEL 表达式指纹（xray/afrog 风格）一键导入转为规则，Cookie 注入绕过浏览器请求限制。整站指纹按域名去重，同类命中不刷屏。

浏览目标站点时自动采集敏感信息、识别技术栈指纹，覆盖反射型 XSS 的发现、WAF 绕过 POC 生成与后台标签主动验证（实测弹窗才标记"已验证"）。

[![Version](https://img.shields.io/badge/version-1.5.0-blue)](https://github.com/p8mpkin-sketch/nothing)
[![Manifest](https://img.shields.io/badge/manifest-v3-green)](https://developer.chrome.com/docs/extensions/mv3/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

---

## ✨ 核心功能

### 🔍 信息采集
- **20+ 正则分类器**：覆盖 API 接口、凭据密钥（Anthropic/OpenAI/AWS/Slack/JWT 等 30+ 种）、内网 IP、邮箱、手机号、路径等
- **Webpack 分块枚举**：解析 chunk map，递归抓取懒加载 JS 模块，提升 SPA 接口覆盖
- **Vue Router 路由提取**：嵌套路由重建，拼出完整前端路由路径
- **降噪过滤**：API 按查询参数键去重、IP 前导零排除、文档文件过滤裸配置名

### 🎯 主动探测与指纹
- **规则引擎**：自定义路径 + 匹配模式主动发包探测，支持递归深度
- **CEL 指纹导入**：粘贴 xray/afrog 风格指纹，内置解析器一键转为探测规则
- **技术栈指纹**：响应头/Cookie/HTML 多维度识别，覆盖 Spring Boot、Jenkins、GitLab、Kong、APISIX、宝兰德、TongWeb 等
- **Cookie 注入**：通过 declarativeNetRequest 绕过浏览器 fetch 的 forbidden header 限制

### 💉 XSS 检测与 POC 主动验证
- **静态检测器**：覆盖 HTML 标签注入、属性注入、JS 字符串注入、DOM XSS、过滤绕过 5 种类型
- **WAF 绕过 POC**：Unicode 混淆关键字 + tagged template 免括号调用 + 对象上下文自动闭合
- **POC 主动验证**：后台标签实测每条 POC 是否真正弹窗，只保留实测能打的，打不动/被拦的直接丢弃
- **自纠正**：检测器上下文判断出错时，自动把真正能弹的那条 POC 提为主推

### 🤖 AI 辅助
- **误报过滤**：扫描结果二次清洗，去掉噪点
- **漏洞分析**：提取 JS source/sink 代码块提交大模型分析
- **多服务商**：支持 OpenAI、Anthropic、DeepSeek、智谱 GLM、自定义（OpenAI 兼容）
- **失败降级**：AI 不可用时自动回退为纯静态检测

### 📦 备份文件扫描
- 自动探测 `.git`、`.svn`、`.env`、备份压缩包等敏感路径
- AI 二次过滤排除 404 页面和默认错误页

---

## 🚀 快速开始

### 安装

```bash
# 1. 克隆仓库
git clone https://github.com/p8mpkin-sketch/nothing.git
cd nothing

# 2. 安装依赖
npm install

# 3. 构建
npm run build
```

然后：
1. 打开 Chrome，地址栏输入 `chrome://extensions/`
2. 开启「开发者模式」
3. 点击「加载已解压的扩展程序」
4. 选择项目的 `dist/` 目录

### 使用

打开任意网页，点击扩展栏的 N 图标，Nothing 自动扫描并展示结果：

- **扫描**：高危/中危/低危三级分类，支持搜索、复制全部
- **漏洞**：XSS 检测结果，含置信度、数据流分析、POC 列表
- **备份文件**：敏感路径泄露探测
- **指纹**：技术栈识别结果
- **命中日志**：规则引擎命中记录
- **设置**：扫描开关、AI 配置、POC 验证

---

## 🏗️ 架构

```
┌──────────────────────────────────────────┐
│  UI 层（popup + options）                 │
│  React 组件，通过 chrome.runtime.send-    │
│  Message 和 background 通信               │
├──────────────────────────────────────────┤
│  Content Script 层（页面注入）            │
│  DOM 扫描、参数采集、内联脚本片段提取、    │
│  Webpack/Vue Router 解析                  │
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
│   ├── manifest.json          # 扩展声明（权限、入口）
│   └── poc-hook.js            # POC 验证 MAIN world alert hook
├── src/
│   ├── background/            # Service Worker
│   │   ├── index.js           # 主入口：路由、AI、XSS 编排
│   │   ├── scanner.js         # 主动扫描器
│   │   ├── ruleEngine.js      # 规则引擎（匹配、去重、缓存）
│   │   ├── staticXssDetector.js  # 静态 XSS 检测
│   │   ├── pocVerifier.js     # POC 主动验证
│   │   ├── fingerprint.js     # 技术栈指纹提取
│   │   ├── networkMonitor.js  # 网络流量监听
│   │   ├── backupScanner.js   # 备份文件扫描
│   │   ├── siteAnalysis.js    # ICP 备案、IP 归属查询
│   │   ├── probeRegistry.js   # 探针注册表
│   │   └── urlParser.js       # URL 层级解析
│   ├── content/               # Content Script
│   │   ├── index.js           # DOM 扫描、参数采集
│   │   ├── scanner.config.js  # 20+ 分类器正则
│   │   └── scanner.filter.js  # 分类器过滤
│   ├── popup/                 # 弹出窗口（主 UI）
│   │   ├── App.jsx            # 全部 UI 逻辑
│   │   └── main.jsx           # React 入口
│   ├── options/               # 选项页
│   │   ├── App.jsx
│   │   ├── RuleEditor.jsx     # 规则编辑器
│   │   ├── ExclusionManager.jsx
│   │   ├── LogViewer.jsx
│   │   └── UsageGuide.jsx
│   └── utils/
│       ├── aiProviders.js     # AI 服务商注册表
│       ├── exclusionMatcher.js
│       └── fingerprintImporter.js  # CEL→规则引擎翻译器
└── vite.config.js
```

---

## 📋 版本更新

### V1.5.0 — 2026-07-01
**类型：大版本功能升级（XSS POC 主动验证）**
- 新增 POC 主动验证：后台标签逐条加载候选 POC，实测是否触发弹窗
- MAIN world alert hook（`poc-hook.js`），不真弹窗、不卡后台标签
- 验证通过只保留能打的 POC，自动丢弃打不动/被 WAF 拦的
- 自纠正：检测器上下文猜错时自动把能弹的 POC 提为主推，置信度 98%
- 新增设置开关「POC 主动验证」（默认开启）

### V1.4.0 — 2026-05-01
**类型：大版本功能升级（XSS 检测质量优化）**
- 消除属性注入子串碰撞误报（`message=www` 命中 href 里的 `www`）
- XSS 结果按类型+source+sink 去重
- WAF 感知 POC：unicode 混淆 + tagged template 免括号 + 对象上下文自动闭合
- 主 POC 一条最可能打通的，附 2 条兜底，不再堆死模板

### V1.3.2 — 2026-03-15
**类型：小优化**
- 降噪：文档文件正则要求路径含 `/`，移除 csv/conf/ini/yml/yaml
- 文档文件危险级从中危降为低危

### V1.3.1 — 2026-03-01
**类型：小优化**
- 修复 IP 分类误报：禁止前导零（`04.04.06.05` 不再匹配），只保留内网 IP 作为中危

### V1.3.0 — 2026-02-15
**类型：大版本功能升级（吸收被动提取广度）**
- Webpack 分块枚举（单页上限 150 个 JS）
- Vue Router 嵌套路由提取
- API 按查询参数键去重
- 密钥模式库扩充（Anthropic/OpenAI/Slack/SendGrid 等）
- JS 抓取兜底：executeScript 带 cookie 回退
- 技术指纹增强（Spring Boot Actuator/Jenkins/GitLab/Kong/APISIX 等）

<details>
<summary>更早版本（点击展开）</summary>

### V1.2.7 — 2026-01-20
- 每个分类新增「复制全部」按钮
- 新增「文档文件」分类

### V1.2.6 — 2026-01-05
- 修复 SW 回收导致去重缓存丢失、同 URL 重复告警

### V1.2.5 — 2025-12-20
- 修复 ICP 备案查询，新增站点信息条

### V1.2.4 — 2025-12-05
- 新增「整站指纹」同域名只报一次

### V1.2.3 — 2025-11-20
- 修复 Cookie/Set-Cookie 主动探测指纹无法命中

### V1.2.2 — 2025-11-08
- CEL 表达式指纹导入（xray/afrog 风格）

### V1.2.1 — 2025-10-25
- AI 服务商兼容：新增 DeepSeek、智谱 GLM

### V1.2.0 — 2025-10-10 基线版本
- 扫描、AI 分析、规则引擎、备份扫描、动态/深度扫描

</details>

**版本规则**：小优化 → patch 递增（1.2.0→1.2.1），大功能 → minor 递增（1.2.x→1.3.0）。

---

## 🔧 技术栈

- **框架**：Chrome Extension Manifest V3 + React 18 + Vite 5
- **AI**：OpenAI / Anthropic / DeepSeek / 智谱 GLM 多服务商适配
- **依赖**：js-yaml（指纹解析）
- **权限**：scripting、declarativeNetRequest、webRequest、tabs、storage、notifications、offscreen

---

## 📄 License

MIT © p8mpkin-sketch
