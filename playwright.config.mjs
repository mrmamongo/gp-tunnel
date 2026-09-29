import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests',
  timeout: 20_000,
  use: { baseURL: 'http://127.0.0.1:1421', viewport: { width: 340, height: 720 }, ...(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {}) },
  webServer: { command: 'pnpm exec vite preview --host 127.0.0.1 --port 1421 --strictPort', url: 'http://127.0.0.1:1421', reuseExistingServer: !process.env.CI },
});
