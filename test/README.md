# 测试基建

回归护栏,专门守住本项目的核心卖点:**检测精度 / 去误报**。
每次"收紧检测降误报"的改动,都应先有一条测试把现状行为锁死,再改。

## 跑

```bash
npm test          # 单次跑全部
npm run test:watch # 监听模式,改代码即时反馈
```

vitest,node 环境,无需 DOM。配置见根目录 [`vitest.config.js`](../vitest.config.js);
[`test/setup.js`](./setup.js) 提供最小 `chrome` stub(被测模块的 `chrome.*` 调用都在
函数内且 try/catch,import 时不触发,stub 只兜底 debounce 定时器)。

## 覆盖的纯逻辑模块

| 文件 | 被测模块 | 重点 |
|---|---|---|
| `urlParser.test.js` | `urlParser` | 父目录枚举、静态资源跳过、非 http 协议 |
| `matchHelper.test.js` | `matchHelper` | regex/keyword/空匹配、status 的 and/or 条件、非法 regex 不抛 |
| `pocEngine.test.js` | `pocEngine` | 上下文解析、编码→不可利用、POC 生成与去重、参数提取偏好最长值 |
| `staticXssDetector.test.js` | `staticXssDetector` | 白名单、守卫、**误报语料**(`isRealXssContext`) |
| `detectionPipeline.test.js` | `detectionPipeline` | 端到端:反射发现→上下文→POC,编码反射不产出 |

## 误报语料(重点约定)

`staticXssDetector.test.js` 里有两组数据驱动用例:

- `notXss` —— "这类上下文不该报"(实体编码 / input value 属性内 / 注释内 / 纯文本无 payload)
- `isXss` —— "这类确实该报"(反射进 `<script>` / 参数值自带标签)

**每定位到一个误报,就往 `notXss` 加一行 `[描述, 上下文片段, 参数值]`**;
每修复一个漏报,往 `isXss` 加一行。这样每次收紧检测都有护栏,不会把之前能打的
真阳性误杀。pocEngine 的编码判定同理,在 `pocEngine.test.js` 的"误报治理"组里扩充。

## 原则

- 测试锚定**当前真实行为**(回归基线),不是锚定理想行为。改了行为就同步改断言,
  并在 commit 里说清为什么。
- 只测纯逻辑;依赖 `chrome.tabs` 真开标签页的 POC 主动验证(`pocVerifier`)不在此列,
  那部分靠手工 / 真实页面验证。
