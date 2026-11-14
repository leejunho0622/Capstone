/* =========================================================
   공통 HTTP 클라이언트
   - 타임아웃, AbortSignal, 에러 타입 통일
   - API_BASE 는 기본적으로 Vite 프록시(/api → 백엔드)를 사용
   ========================================================= */

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "";
const DEFAULT_TIMEOUT_MS = 8000;

export class ApiError extends Error {
  readonly status: number;
  readonly url: string;

  constructor(message: string, status: number, url: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.url = url;
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function buildQuery(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

interface RequestOptions {
  query?: Query;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export async function http<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const url = `${API_BASE}${path}${buildQuery(options.query)}`;
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(new DOMException("timeout", "TimeoutError")),
    options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  );
  const onAbort = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const res = await fetch(url, {
      method: options.method ?? "GET",
      headers:
        options.body !== undefined
          ? { "Content-Type": "application/json", Accept: "application/json" }
          : { Accept: "application/json" },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });

    if (!res.ok) {
      // Vite 프록시는 백엔드가 꺼져 있으면 502/503/504 를 돌려줌 → 연결 불가로 표시
      if ([502, 503, 504].includes(res.status) && !res.headers.get("content-type")?.includes("json")) {
        throw new ApiError("백엔드 서버(8080)에 연결할 수 없습니다", 0, url);
      }
      let message = `${res.status} ${res.statusText}`;
      try {
        const err = await res.json();
        if (err?.message) message = String(err.message);
      } catch {
        /* 본문 없음 */
      }
      throw new ApiError(message, res.status, url);
    }

    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError" && options.signal?.aborted) {
      throw err; // 호출자가 취소한 경우는 그대로 전달
    }
    const reason =
      err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError")
        ? "요청 시간 초과"
        : "서버에 연결할 수 없습니다";
    throw new ApiError(reason, 0, url);
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

export function isAbort(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}
