import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 백엔드 주소는 환경변수로 바꿀 수 있습니다.
//   예) VITE_API_TARGET=http://192.168.0.10:8080 npm run dev
//   목업 서버로 시연할 때: npm run mock  (다른 터미널에서 npm run dev)
const apiTarget = process.env.VITE_API_TARGET ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 1000,
  },
});
