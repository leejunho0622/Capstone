/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 백엔드 주소를 직접 지정할 때 (기본값: Vite 프록시 /api 사용) */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
