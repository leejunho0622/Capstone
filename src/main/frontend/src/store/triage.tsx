import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { saveTriage } from "../api/client";
import type { TriageInfo, TriageStatus } from "../api/types";
import { ApiError } from "../api/http";
import { readStorage, writeStorage } from "../hooks/useLocalStorage";
import { useLiveData } from "./liveData";
import { useSettings } from "./settings";

/* =========================================================
   경보 처리(Triage) 상태
   - 기본: 서버(incident_triage 테이블)에 저장 → 관제요원끼리 공유
   - 서버에 API 가 없으면(404) 브라우저에 저장하는 '로컬 모드' 로 자동 전환
   - 화면은 먼저 바꾸고(낙관적 업데이트) 저장 실패 시 되돌림
   ========================================================= */

export const TRIAGE_META: Record<TriageStatus, { label: string; dot: string }> = {
  NEW: { label: "신규", dot: "bg-sev-critical" },
  ACK: { label: "확인 중", dot: "bg-sev-medium" },
  RESOLVED: { label: "조치 완료", dot: "bg-sev-low" },
  FALSE_POSITIVE: { label: "오탐", dot: "bg-faint" },
};

export const TRIAGE_ORDER: TriageStatus[] = ["NEW", "ACK", "RESOLVED", "FALSE_POSITIVE"];

type Mode = "server" | "local";

interface TriageContextValue {
  mode: Mode;
  get: (id: string) => TriageInfo | null;
  statusOf: (id: string) => TriageStatus;
  setStatus: (ids: string[], status: TriageStatus, note?: string) => Promise<void>;
  setNote: (id: string, note: string) => Promise<void>;
  clearLocal: () => void;
}

const TriageContext = createContext<TriageContextValue | null>(null);
const LOCAL_KEY = "triage-local";

type Stored = Record<string, Omit<TriageInfo, "updatedAt"> & { updatedAt: string | null }>;

const newer = (a: TriageInfo | null | undefined, b: TriageInfo | null | undefined) => {
  if (!a) return b ?? null;
  if (!b) return a;
  return (a.updatedAt?.getTime() ?? 0) >= (b.updatedAt?.getTime() ?? 0) ? a : b;
};

export function TriageProvider({ children }: { children: ReactNode }) {
  const { alerts } = useLiveData();
  const { settings } = useSettings();
  const [mode, setMode] = useState<Mode>("server");
  const [overrides, setOverrides] = useState<Record<string, TriageInfo>>(() => {
    const stored = readStorage<Stored>(LOCAL_KEY, {});
    return Object.fromEntries(
      Object.entries(stored).map(([k, v]) => [k, { ...v, updatedAt: v.updatedAt ? new Date(v.updatedAt) : null }])
    );
  });

  useEffect(() => {
    if (mode === "local") {
      writeStorage(
        LOCAL_KEY,
        Object.fromEntries(
          Object.entries(overrides).map(([k, v]) => [k, { ...v, updatedAt: v.updatedAt?.toISOString() ?? null }])
        )
      );
    }
  }, [mode, overrides]);

  const serverMap = useMemo(() => new Map(alerts.map((a) => [a.id, a.triage])), [alerts]);

  const get = useCallback(
    (id: string) => newer(overrides[id], serverMap.get(id)),
    [overrides, serverMap]
  );

  const upsert = useCallback(
    async (id: string, patch: { status?: TriageStatus; note?: string }) => {
      const prev = get(id);
      const next: TriageInfo = {
        status: patch.status ?? prev?.status ?? "NEW",
        note: patch.note ?? prev?.note ?? "",
        assignee: settings.analyst,
        updatedAt: new Date(),
      };
      setOverrides((o) => ({ ...o, [id]: next }));
      if (mode === "local") return;
      try {
        const saved = await saveTriage(id, { status: next.status, note: next.note, assignee: next.assignee });
        setOverrides((o) => ({ ...o, [id]: { ...saved, updatedAt: saved.updatedAt ?? next.updatedAt } }));
      } catch (err) {
        // 404/405: triage API 없음, 503: incident_triage 테이블 없음 → 브라우저 저장으로 계속
        if (err instanceof ApiError && [404, 405, 503].includes(err.status)) {
          setMode("local");
          return;
        }
        setOverrides((o) => {
          const copy = { ...o };
          delete copy[id];
          return copy;
        });
        throw err;
      }
    },
    [get, mode, settings.analyst]
  );

  const value = useMemo<TriageContextValue>(
    () => ({
      mode,
      get,
      statusOf: (id) => get(id)?.status ?? "NEW",
      setStatus: async (ids, status, note) => {
        const results = await Promise.allSettled(
          ids.map((id) => upsert(id, note !== undefined ? { status, note } : { status }))
        );
        const failed = results.find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;
        if (failed) throw failed.reason;
      },
      setNote: (id, note) => upsert(id, { note }),
      clearLocal: () => {
        setOverrides({});
        writeStorage(LOCAL_KEY, {});
        setMode("server");
      },
    }),
    [mode, get, upsert]
  );

  return <TriageContext.Provider value={value}>{children}</TriageContext.Provider>;
}

export function useTriage() {
  const ctx = useContext(TriageContext);
  if (!ctx) throw new Error("useTriage must be used inside TriageProvider");
  return ctx;
}
