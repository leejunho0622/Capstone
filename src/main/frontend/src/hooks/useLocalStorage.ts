import { useCallback, useEffect, useState } from "react";

const PREFIX = "gwanjetap:";

export function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(PREFIX + key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

export function writeStorage<T>(key: string, value: T) {
  try {
    window.localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    /* 저장 공간 부족/사생활 보호 모드 - 무시 */
  }
}

/** localStorage 와 동기화되는 state (다른 탭에서 바꿔도 반영) */
export function useLocalStorage<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readStorage(key, fallback));

  useEffect(() => {
    writeStorage(key, value);
  }, [key, value]);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === PREFIX + key && e.newValue !== null) {
        try {
          setValue(JSON.parse(e.newValue) as T);
        } catch {
          /* 무시 */
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [key]);

  const reset = useCallback(() => setValue(fallback), [fallback]);
  return [value, setValue, reset] as const;
}
