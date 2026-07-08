# Nothing 插件开发手册

写这份文档的目的是以后自己和同事要往 Nothing 里加新能力的时候，不用重新读一遍源码。

## 项目结构

```
nothing-plugin/
├── public/
│   ├── manifest.json        # 扩展声明（权限、版本、入口）
│   └── poc-hook.js          # POC 验证用的 MAIN world alert hook
├── src/
│   ├── background/          # Service Worker 后台
│   │   ├── index.js         # 主入口：消息路由、AI 调用、XSS 检测编排、POC 后处理
│   │   ├── scanner.js       # 主动扫描器（规则引擎驱动的路径探测）
│   │   ├── ruleEngine.js    # 规则引擎（匹配、去重、持久化缓存）
│   │   ├── staticXssDetector.js  # 静态 XSS 检测（不依赖 AI）
│   │   ├── pocVerifier.js   # POC 主动验证（后台标签实测弹窗）
│   │   ├── fingerprint.js   # 响应头/Cookie 技术栈指纹提取
│   │   ├── networkMonitor.js # 网络流量监听、JS 文件收集
│   │   ├── backupScanner.js # 备份文件/敏感路径扫描
│   │   ├── siteAnalysis.js  # ICP 备案查询、IP 归属、根域名解析
│   │   ├── probeRegistry.js # 探针注册表（轻量）
│   │   └── urlParser.js     # URL 层级解析
│   ├── content/             # 页面注入脚本（content script）
│   │   ├── index.js         # 主逻辑：DOM 扫描、参数采集、内联脚本片段提取
│   │   ├── scanner.config.js # 分类器正则配置（20+ 个分类）
│   │   └── scanner.filter.js # 分类器白名单/黑名单过滤
│   ├── popup/               # 弹出窗口 UI（主界面）
│   │   ├── App.jsx          # 全部 UI 逻辑（扫描/备份/指纹/日志/排除/设置）
│   │   └── main.jsx         # React 入口
│   ├── options/             # 选项页（独立页面，实际用得少）
│   │   ├── App.jsx          # 选项页主组件
│   │   ├── RuleEditor.jsx   # 规则编辑器
│   │   ├── ExclusionManager.jsx  # 排除项管理
│   │   ├── LogViewer.jsx    # 命中日志查看
│   │   └── UsageGuide.jsx   # 使用指南
│   └── utils/
│       ├── aiProviders.js   # AI 服务商注册表
│       ├── exclusionMatcher.js # 排除项匹配
│       └── fingerprintImporter.js # CEL 表达式→规则引擎的翻译器
├── dist/                    # 构建产物（Chrome 加载这个目录）
└── vite.config.js
```

## 怎么加一个新的扫描分类

比如想加一个"身份证号"的分类，需要改两个文件：

### 1. scanner.config.js — 定义正则

```js
// 在 window.SCANNER_CONFIG 里加一项
idCard: {
    name: '身份证号',
    patterns: [
        /[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]/g
    ]
}
```

pattern 必须是全局正则（带 `g` 标志），content script 用 `matchAll` 遍历。

### 2. App.jsx — 决定危险等级和展示位置

在 `RISK_GROUPS` 里把 `idCard` 放进 high/medium/low 其中一个数组：

```js
const RISK_GROUPS = {
  high: ['credential', 'jwt', 'idCard', ...],
  medium: ['ip', 'email', ...],
  low: ['api', 'url', ...],
}
```

在 `categoryConfidence` 里给个默认权重（影响排序）：

```js
const categoryConfidence = {
  ...
  idCard: 'high',
}
```

构建后 content script 会自动采集、popup 会自动展示，不需要改 background。

### 3. AI 过滤（可选）

如果新分类容易产生误报（比如身份证正则可能匹配到测试数据），在 `index.js` 的 `callAI` filter prompt 里加一条过滤规则，告诉 AI 什么情况该删。

## 怎么加一个新的 AI 服务商

只改 `src/utils/aiProviders.js`。在 `PROVIDERS` 对象里加一项：

```js
newProvider: {
    name: '新服务商',
    baseUrl: 'https://api.xxx.com',
    chatPath: '/v1/chat/completions',
    defaultModel: 'xxx-model',
    modelPlaceholder: '模型 ID',
    keyPlaceholder: 'sk-...',
    protocol: 'openai',  // 'openai' 或 'anthropic'
    headers: (apiKey) => ({ Authorization: `Bearer ${apiKey}` }),
    buildBody: (model, messages) => ({ model, messages, ... }),
}
```

`protocol: 'openai'` 走 OpenAI 兼容格式（绝大多数国产模型都用这个），`protocol: 'anthropic'` 走 Anthropic Messages API。

然后给 `aiProviders.js` 里的 `JSON_IMPORT_KEY_MAP` 加一条环境变量名映射（如果有常见命名的话），这样用户 JSON 导入设置时能自动识别。

## 怎么加一种新的 XSS 检测类型

改 `src/background/staticXssDetector.js`：

1. 在 `analyze()` 方法里加一个新的检测调用，参考现有的五个检测方法的写法
2. 新检测方法的核心流程：
   - 遍历 params，检查值是否在 snippet 中反射
   - 判断上下文（JS 字符串/属性/HTML/DOM sink）
   - 构造闭合 payload → 调 `generatePocUrls()` 生成完整 URL
   - push 到 `result.vulnerabilities`
3. 在 `buildJsStringPayloads()` 或新增一个 payload 构造方法里，给出该类型的 WAF 绕过 payload（主推 + 兜底）
4. `analyze()` 出口会自动去重，不用额外处理

POC 主动验证（pocVerifier.js）不需要改——它自动对所有 `type` 含 `xss` 的漏洞生效。

## 怎么改 POC 验证的行为

`src/background/pocVerifier.js`：

- `maxPocsPerFinding`：每个漏洞最多测几条 POC（默认 3）
- `totalBudget`：单次扫描总共打开多少个标签（默认 8）
- `loadTimeout`：每个标签等多久（默认 6000ms）
- `registerHook` 注入的 hook 文件在 `public/poc-hook.js`，如果想加对其他弹窗函数的 hook（比如 `window.open`），改那个文件就行

验证逻辑：找到第一条能弹的 POC 就停（`break`），然后**只保留验证通过的**，其余丢弃。如果想保留候选兜底，把 `t.v.pocs = [...verified]` 改成 `t.v.pocs = [...verified, ...rest]`。

## 怎么加新的指纹导入格式

`src/utils/fingerprintImporter.js` 目前支持 CEL 表达式（xray/afrog 风格）。要加新格式：

1. 新增一个解析函数（参考 `parseCelExpression`），把新格式翻译成内部规则结构：
   ```js
   { name, path, method, matchHeaders, matchBody, statusCode }
   ```
2. 在 `parseFingerprint` 里加格式判断分支
3. App.jsx 里的导入弹窗加一个格式选择（如果需要用户手动选的话）

## 构建和调试

```bash
npm run build          # 构建到 dist/
```

开发时不建议 `npm run dev`，因为 MV3 的 service worker 对 HMR 支持很差。实测最稳的方式是：

1. 改代码
2. `npm run build`
3. `chrome://extensions/` → 点 Nothing 的刷新按钮
4. 去目标页面 F5，看 popup

调试技巧：
- background 日志在 `chrome://extensions/` → Nothing → "Service Worker" 链接里看
- content script 日志在目标页面的 F12 Console 看
- popup 日志右键点扩展图标 → "检查弹出内容"
- node 路径在 `/opt/homebrew/bin/node`（Mac Apple Silicon）
