import { defineConfig } from 'vitest/config'

// 独立于 vite.config.js（构建配置），避免 react 插件 / content-script 多入口
// 影响测试运行。vitest 优先读本文件且不与 vite.config.js 合并。
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    setupFiles: ['./test/setup.js'],
    include: ['test/**/*.test.js'],
  },
})
