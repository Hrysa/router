import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://172.20.252.85:8443',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
