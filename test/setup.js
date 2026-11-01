// 全局 chrome stub。
// 被测模块（pocEngine 的 WafStrategyManager、pocVerifier）在函数内部调用
// chrome.storage / chrome.tabs，且都用 try/catch 包着。import 时不触发，
// 但 recordSuccess/recordFailure 会起一个 2s 的 debounce 定时器去写 storage，
// 若测试结束后定时器仍 fire 且 chrome 未定义会抛错。这里给个最小 stub 兜底。
if (!globalThis.chrome) {
  globalThis.chrome = {
    storage: {
      local: {
        get: (_key, cb) => { if (typeof cb === 'function') cb({}); return Promise.resolve({}) },
        set: () => Promise.resolve(),
      },
    },
    tabs: {
      create: (_o, cb) => cb && cb(null),
      update: (_i, _o, cb) => cb && cb(null),
      remove: (_i, cb) => cb && cb(),
      onUpdated: { addListener() {}, removeListener() {} },
    },
    runtime: {},
  }
}
