import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { useLocalStorage } from "../hooks/useLocalStorage";
import type { Severity } from "../api/types";

export type ThemeMode = "light" | "dark" | "system";

export interface Settings {
  /** 화면 테마 (기본: 밝은 테마) */
  theme: ThemeMode;
  /** 실시간 갱신 주기 (ms) */
  pollMs: number;
  /** 실시간 갱신 일시정지 */
  paused: boolean;
  /** 경보 조회 범위 (최근 N시간) */
  alertWindowHours: number;
  /** 이 등급 이상이면 화면/소리 경보 */
  alarmSeverity: Extract<Severity, "critical" | "high" | "medium">;
  visualAlarm: boolean;
  soundAlarm: boolean;
  voiceAlarm: boolean;
  volume: number; // 0~1
  /** 경보 처리 기록에 남길 분석가 이름 */
  analyst: string;
}

export const DEFAULT_SETTINGS: Settings = {
  theme: "light",
  pollMs: 5000,
  paused: false,
  alertWindowHours: 24,
  alarmSeverity: "high",
  visualAlarm: true,
  soundAlarm: true,
  voiceAlarm: true,
  volume: 0.7,
  analyst: "관제요원",
};

interface SettingsContextValue {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
  reset: () => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [stored, setStored, reset] = useLocalStorage<Settings>("settings", DEFAULT_SETTINGS);
  const theme = stored.theme ?? DEFAULT_SETTINGS.theme;

  // <html data-theme="light|dark"> 적용. system 이면 OS 설정을 따라가고 바뀌면 즉시 반영
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const resolved = theme === "system" ? (media.matches ? "dark" : "light") : theme;
      document.documentElement.dataset.theme = resolved;
    };
    apply();
    if (theme !== "system") return;
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);

  const value = useMemo<SettingsContextValue>(
    () => ({
      // 새 설정 항목이 추가되어도 기본값으로 채워지도록 병합
      settings: { ...DEFAULT_SETTINGS, ...stored },
      update: (patch) => setStored((prev) => ({ ...DEFAULT_SETTINGS, ...prev, ...patch })),
      reset,
    }),
    [stored, setStored, reset]
  );
  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings() {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings must be used inside SettingsProvider");
  return ctx;
}
