/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Pretendard Variable",
          "Pretendard",
          "Apple SD Gothic Neo",
          "Malgun Gothic",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "D2Coding",
          "Consolas",
          "ui-monospace",
          "monospace",
        ],
      },
      colors: {
        // 화면 바탕/표면 (src/index.css 의 CSS 변수와 연결)
        canvas: "rgb(var(--c-base) / <alpha-value>)",
        surface: "rgb(var(--c-surface) / <alpha-value>)",
        raised: "rgb(var(--c-raised) / <alpha-value>)",
        line: "rgb(var(--c-line) / <alpha-value>)",
        ink: "rgb(var(--c-ink) / <alpha-value>)",
        muted: "rgb(var(--c-muted) / <alpha-value>)",
        faint: "rgb(var(--c-faint) / <alpha-value>)",
        accent: "rgb(var(--c-accent) / <alpha-value>)",
        brand: "rgb(var(--c-brand) / <alpha-value>)",
        overlay: "rgb(var(--overlay) / <alpha-value>)",
        // 위험도 (상태 색상 - 차트 시리즈 색으로 재사용 금지)
        sev: {
          critical: "rgb(var(--c-sev-critical) / <alpha-value>)",
          high: "rgb(var(--c-sev-high) / <alpha-value>)",
          medium: "rgb(var(--c-sev-medium) / <alpha-value>)",
          low: "rgb(var(--c-sev-low) / <alpha-value>)",
          info: "rgb(var(--c-sev-info) / <alpha-value>)",
        },
      },
      keyframes: {
        "live-ping": {
          "0%": { transform: "scale(1)", opacity: "0.7" },
          "80%, 100%": { transform: "scale(2.4)", opacity: "0" },
        },
        "slide-in": {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(-4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "row-flash": {
          "0%": { backgroundColor: "rgb(var(--c-sev-critical) / 0.22)" },
          "100%": { backgroundColor: "transparent" },
        },
        "screen-flash": {
          "0%, 100%": { opacity: "0" },
          "15%, 45%, 75%": { opacity: "0.28" },
          "30%, 60%, 90%": { opacity: "0.06" },
        },
        "alert-pulse": {
          "0%, 100%": { boxShadow: "0 0 0 0 rgb(var(--c-sev-critical) / 0.55)" },
          "50%": { boxShadow: "0 0 0 14px rgb(var(--c-sev-critical) / 0)" },
        },
      },
      animation: {
        "live-ping": "live-ping 1.6s cubic-bezier(0,0,0.2,1) infinite",
        "slide-in": "slide-in 0.22s ease-out",
        "fade-in": "fade-in 0.16s ease-out",
        "row-flash": "row-flash 2.4s ease-out",
        "screen-flash": "screen-flash 1.2s ease-in-out infinite",
        "alert-pulse": "alert-pulse 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
