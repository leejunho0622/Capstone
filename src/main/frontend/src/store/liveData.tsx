import { createContext, useContext, useMemo, useRef, type ReactNode } from "react";
import {
  getIncidents,
  getAttackTypes,
  getHourlyTimeline,
  getSummary,
  getWeeklyTimeline,
} from "../api/client";
import type { Alert, CountPoint, Summary } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useSettings } from "./settings";

/* =========================================================
   실시간 대시보드 데이터
   - 6개 API 를 한 주기에 병렬 조회 (Promise.allSettled)
   - 경보(alerts) = /api/incidents (attack_events 공격 단위)
   - 한 API 가 실패해도 나머지는 갱신 → 부분 장애(degraded) 로 표시
   - 이전 주기 대비 '새로 들어온 경보' 를 계산해 강조/경보에 사용
   ========================================================= */

export type ConnectionState = "connecting" | "live" | "degraded" | "down" | "paused";

interface LiveSnapshot {
  summary?: Summary;
  hourly?: CountPoint[];
  weekly?: CountPoint[];
  attackTypesAll?: CountPoint[];
  attackTypesToday?: CountPoint[];
  alerts?: Alert[];
  failed: string[];
  freshIds: Set<string>;
  initial: boolean;
}

interface LiveDataValue extends Omit<LiveSnapshot, "failed" | "freshIds" | "initial"> {
  alerts: Alert[];
  connection: ConnectionState;
  failedEndpoints: string[];
  lastUpdated: Date | null;
  /** 직전 갱신에서 처음 보인 경보 id (행 강조용) */
  freshIds: Set<string>;
  /** 첫 로딩 이후에 들어온 경보 id 누적 (소리 경보 판단용) */
  isInitialLoad: boolean;
  refresh: () => void;
  errorMessage: string | null;
}

const EMPTY = new Set<string>();
const LiveDataContext = createContext<LiveDataValue | null>(null);

export function LiveDataProvider({ children }: { children: ReactNode }) {
  const { settings } = useSettings();
  const lastGood = useRef<LiveSnapshot>({ failed: [], freshIds: new Set(), initial: true });
  const seenRef = useRef<Set<string> | null>(null);

  const { data, error, lastUpdated, refresh } = usePolling<LiveSnapshot>(
    async (signal) => {
      const tasks = {
        summary: getSummary(signal),
        hourly: getHourlyTimeline(signal),
        weekly: getWeeklyTimeline(signal),
        attackTypesAll: getAttackTypes("all", signal),
        attackTypesToday: getAttackTypes("today", signal),
        alerts: getIncidents({ hours: settings.alertWindowHours, size: 500 }, signal),
      };
      const keys = Object.keys(tasks) as Array<keyof typeof tasks>;
      const results = await Promise.allSettled(Object.values(tasks));

      const next: LiveSnapshot = {
        ...lastGood.current,
        failed: [],
        freshIds: new Set(),
        initial: false,
      };
      results.forEach((r, i) => {
        const key = keys[i];
        if (r.status === "fulfilled") {
          (next as unknown as Record<string, unknown>)[key] = r.value;
        } else {
          next.failed.push(key);
        }
      });
      if (next.failed.length === keys.length) {
        const first = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
        throw first.reason instanceof Error ? first.reason : new Error("모든 API 요청 실패");
      }

      // 새로 들어온 경보 계산 (첫 로딩분은 '새 경보' 로 보지 않음)
      if (next.alerts && next.alerts !== lastGood.current.alerts) {
        const initial = seenRef.current === null;
        const seen = seenRef.current ?? new Set<string>();
        for (const a of next.alerts) {
          if (!seen.has(a.id)) {
            if (!initial) next.freshIds.add(a.id);
            seen.add(a.id);
          }
        }
        seenRef.current = seen;
        next.initial = initial;
      }
      lastGood.current = next;
      return next;
    },
    [settings.alertWindowHours],
    { intervalMs: settings.pollMs, enabled: !settings.paused }
  );

  const connection: ConnectionState = settings.paused
    ? "paused"
    : !data && !error
      ? "connecting"
      : error
        ? "down"
        : data && data.failed.length > 0
          ? "degraded"
          : "live";

  const value = useMemo<LiveDataValue>(
    () => ({
      summary: data?.summary,
      hourly: data?.hourly,
      weekly: data?.weekly,
      attackTypesAll: data?.attackTypesAll,
      attackTypesToday: data?.attackTypesToday,
      alerts: data?.alerts ?? [],
      connection,
      failedEndpoints: error ? ["all"] : (data?.failed ?? []),
      lastUpdated,
      freshIds: data?.freshIds ?? EMPTY,
      isInitialLoad: data?.initial ?? true,
      refresh,
      errorMessage: error?.message ?? null,
    }),
    [data, connection, error, lastUpdated, refresh]
  );

  return <LiveDataContext.Provider value={value}>{children}</LiveDataContext.Provider>;
}

export function useLiveData() {
  const ctx = useContext(LiveDataContext);
  if (!ctx) throw new Error("useLiveData must be used inside LiveDataProvider");
  return ctx;
}
