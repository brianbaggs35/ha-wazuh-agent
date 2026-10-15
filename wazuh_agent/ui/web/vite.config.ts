import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'
import vuetify from 'vite-plugin-vuetify'
import { configDefaults } from 'vitest/config'

export default defineConfig({
  plugins: [vue(), vuetify({ autoImport: true })],
  // Relative asset URLs: Home Assistant serves the page under an ingress path it chooses.
  base: './',
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // For `npm run dev` against a running app: forward the API calls.
    proxy: {
      '/api': { target: process.env.WAZUH_UI_URL ?? 'http://127.0.0.1:8099', changeOrigin: true },
    },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 900 },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['src/test/setup.ts'],
    exclude: [...configDefaults.exclude],
    server: { deps: { inline: ['vuetify'] } },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,vue}'],
      exclude: ['src/**/*.spec.ts', 'src/test/**', 'src/**/types.ts'],
      // lcov.info is read by the Sonar scan; scripts/ci/coverage.sh rewrites its paths to be
      // relative to the repository root.
      reporter: ['text', 'lcov', 'html'],
      thresholds: { lines: 100, functions: 100, branches: 100, statements: 100 },
    },
  },
})
