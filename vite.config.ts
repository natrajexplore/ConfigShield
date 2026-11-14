import { defineConfig } from 'vite';

export default defineConfig({
  build: { target: 'es2022', sourcemap: true, chunkSizeWarningLimit: 900 },
  test: { environment: 'node', include: ['tests/**/*.test.ts'] },
} as never);
