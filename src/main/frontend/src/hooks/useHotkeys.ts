import { useEffect, useRef } from "react";

type Handler = (e: KeyboardEvent) => void;

/**
 * 간단한 단축키 등록
 * - 입력창에 포커스가 있으면 무시 (Escape 제외)
 * - "g a" 처럼 두 글자 연속 입력 지원
 */
export function useHotkeys(map: Record<string, Handler>) {
  const mapRef = useRef(map);
  useEffect(() => {
    mapRef.current = map;
  });

  useEffect(() => {
    let prefix = "";
    let prefixTimer: number | undefined;

    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      const typing =
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable);
      if (typing && e.key !== "Escape") return;

      const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      const combo = prefix ? `${prefix} ${key}` : key;
      const handlers = mapRef.current;

      if (handlers[combo]) {
        e.preventDefault();
        handlers[combo](e);
        prefix = "";
        return;
      }
      if (Object.keys(handlers).some((k) => k.startsWith(`${key} `))) {
        prefix = key;
        window.clearTimeout(prefixTimer);
        prefixTimer = window.setTimeout(() => (prefix = ""), 900);
        return;
      }
      prefix = "";
    };

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.clearTimeout(prefixTimer);
    };
  }, []);
}
