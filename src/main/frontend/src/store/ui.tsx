import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

/* 화면 전역 UI 상태: 상세 패널(경보/플로우), 토스트 */

export interface Toast {
  id: number;
  kind: "info" | "success" | "error";
  message: string;
}

export type DrawerTarget = { kind: "incident" | "flow"; id: string };

interface UiValue {
  /** 상세 패널 이동 기록 (마지막 항목이 현재 화면) */
  drawer: DrawerTarget[];
  openIncident: (id: string) => void;
  openFlow: (flowId: string) => void;
  /** 경보 상세 → 플로우 상세처럼 쌓아서 열기 (뒤로 가기 가능) */
  pushDrawer: (target: DrawerTarget) => void;
  backDrawer: () => void;
  closeDrawer: () => void;
  toasts: Toast[];
  toast: (message: string, kind?: Toast["kind"]) => void;
  dismissToast: (id: number) => void;
}

const UiContext = createContext<UiValue | null>(null);
let toastSeq = 0;

export function UiProvider({ children }: { children: ReactNode }) {
  const [drawer, setDrawer] = useState<DrawerTarget[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismissToast = useCallback((id: number) => {
    setToasts((t) => t.filter((x) => x.id !== id));
  }, []);

  const toast = useCallback(
    (message: string, kind: Toast["kind"] = "info") => {
      const id = ++toastSeq;
      setToasts((t) => [...t.slice(-3), { id, kind, message }]);
      window.setTimeout(() => dismissToast(id), 3500);
    },
    [dismissToast]
  );

  const value = useMemo<UiValue>(
    () => ({
      drawer,
      openIncident: (id) => setDrawer([{ kind: "incident", id }]),
      openFlow: (id) => setDrawer([{ kind: "flow", id }]),
      pushDrawer: (t) => setDrawer((d) => [...d.slice(-9), t]),
      backDrawer: () => setDrawer((d) => d.slice(0, -1)),
      closeDrawer: () => setDrawer([]),
      toasts,
      toast,
      dismissToast,
    }),
    [drawer, toasts, toast, dismissToast]
  );

  return <UiContext.Provider value={value}>{children}</UiContext.Provider>;
}

export function useUi() {
  const ctx = useContext(UiContext);
  if (!ctx) throw new Error("useUi must be used inside UiProvider");
  return ctx;
}
