import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: false,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        options: resolve(__dirname, 'options.html'),
        offscreen: resolve(__dirname, 'src/offscreen/offscreen.html'),
        background: resolve(__dirname, 'src/background/index.js'),
        // Content scripts - built as plain IIFE (no module), injected via manifest
        'scanner.config': resolve(__dirname, 'src/content/scanner.config.js'),
        'scanner.filter': resolve(__dirname, 'src/content/scanner.filter.js'),
        content: resolve(__dirname, 'src/content/index.js'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          // Content scripts must be plain files, not modules
          const contentEntries = ['scanner.config', 'scanner.filter', 'content'];
          if (contentEntries.includes(chunkInfo.name)) {
            return 'assets/[name].js';
          }
          return 'assets/[name].js';
        },
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]',
        // Content scripts cannot use ES modules - use IIFE format
        format: 'es',
      }
    }
  }
})
