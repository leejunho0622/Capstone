import { useCallback, useEffect, useRef, useState } from "react";
import { isAbort } from "../api/http";

interface PollingOptions {
  intervalMs: number;
  enabled?: boolean;
  /** 실패 시 다음 시도까지 간격을 2배씩 늘리는 최대값 */
  maxBackoffMs?: number;
}

export interface PollingState<T> {
  data: T | undefined;
  error: Error | null;
  loading: boolean;
  lastUpdated: Date | null;
  refresh: () => void;
}

/**
 * 주기적 조회 훅
 * - 이전 요청이 끝난 뒤 다음 요청 예약 (요청이 겹치지 않음)
 * - 탭이 보이지 않으면 멈추고, 다시 보이면 즉시 갱신
 * - 실패하면 지수 백오프 (서버가 죽었을 때 요청 폭주 방지)
 * - deps 가 바뀌면 진행 중 요청을 취소하고 새로 조회
 */
export function usePolling<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
  { intervalMs, enabled = true, maxBackoffMs = 60_000 }: PollingOptions
): PollingState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [tick, setTick] = useState(0);

  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let controller: AbortController | null = null;
    let failures = 0;

    const schedule = (ms: number) => {
      window.clearTimeout(timer);
      if (!cancelled && enabled) timer = window.setTimeout(run, ms);
    };

    const run = async () => {
      if (cancelled) return;
      if (document.hidden) return; // visibilitychange 에서 재개
      controller?.abort();
      controller = new AbortController();
      setLoading(true);
      try {
        const result = await fetcherRef.current(controller.signal);
        if (cancelled) return;
        failures = 0;
        setData(result);
        setError(null);
        setLastUpdated(new Date());
      } catch (err) {
        if (cancelled || isAbort(err)) return;
        failures += 1;
        setError(err instanceof Error ? err : new Error(String(err)));
      } finally {
        if (!cancelled) {
          setLoading(false);
          const backoff = Math.min(maxBackoffMs, intervalMs * 2 ** Math.max(0, failures - 1));
          schedule(failures > 0 ? backoff : intervalMs);
        }
      }
    };

    const onVisible = () => {
      if (!document.hidden && enabled) {
        window.clearTimeout(timer);
        void run();
      }
    };

    // 일시정지 상태여도 '최초 1회' 혹은 수동 새로고침은 수행 (schedule 이 enabled 를 확인)
    void run();
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      controller?.abort();
      document.removeEventListener("visibilitychange", onVisible);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, enabled, maxBackoffMs, tick, ...deps]);

  return { data, error, loading, lastUpdated, refresh };
}
