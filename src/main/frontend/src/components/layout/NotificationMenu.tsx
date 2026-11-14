import { useEffect, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { CheckCheck, X } from "lucide-react";
import type { Alert } from "../../api/types";
import { useLiveData } from "../../store/liveData";
import { useSettings } from "../../store/settings";
import { useUi } from "../../store/ui";
import { SEVERITY_CLASS, SEVERITY_META } from "../../lib/severity";
import { endpoint, fmtAgo } from "../../lib/format";
import { attackInfo } from "../../lib/attackTypes";
import { EmptyState } from "../ui";

export interface NotificationItem {
  alert: Alert;
  unread: boolean;
}

/** 실제 경보 데이터에서 알림 목록 생성 (설정한 경보 등급 이상만) */
// eslint-disable-next-line react-refresh/only-export-components
export function useNotifications(lastSeen: number): NotificationItem[] {
  const { alerts } = useLiveData();
  const { settings } = useSettings();
  return useMemo(() => {
    const minRank = SEVERITY_META[settings.alarmSeverity].rank;
    return alerts
      .filter((a) => SEVERITY_META[a.severity].rank >= minRank)
      .sort((a, b) => (b.lastSeen?.getTime() ?? 0) - (a.lastSeen?.getTime() ?? 0))
      .slice(0, 30)
      .map((a) => ({ alert: a, unread: (a.firstSeen?.getTime() ?? 0) > lastSeen }));
  }, [alerts, settings.alarmSeverity, lastSeen]);
}

export function NotificationMenu({
  lastSeen,
  onMarkAllRead,
  onClose,
}: {
  lastSeen: number;
  onMarkAllRead: () => void;
  onClose: () => void;
}) {
  const items = useNotifications(lastSeen);
  const { settings } = useSettings();
  const { openIncident } = useUi();
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement>(null);
  const unread = items.filter((i) => i.unread).length;

  // 바깥 클릭 시 닫기
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const t = window.setTimeout(() => document.addEventListener("mousedown", onDown), 0);
    return () => {
      window.clearTimeout(t);
      document.removeEventListener("mousedown", onDown);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="absolute right-0 top-10 z-40 w-[380px] animate-fade-in overflow-hidden rounded-lg border border-line bg-surface shadow-2xl"
      role="dialog"
      aria-label="알림"
    >
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <div>
          <p className="text-sm font-semibold">알림</p>
          <p className="text-[11px] text-muted">
            {SEVERITY_META[settings.alarmSeverity].label} 이상 · 읽지 않음 {unread}건
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button className="btn btn-ghost h-7 px-2" onClick={onMarkAllRead} disabled={unread === 0}>
            <CheckCheck size={14} /> 모두 읽음
          </button>
          <button className="btn btn-ghost h-7 w-7 px-0" onClick={onClose} aria-label="닫기">
            <X size={14} />
          </button>
        </div>
      </div>

      <ul className="max-h-[420px] overflow-y-auto">
        {items.length === 0 && <EmptyState title="새 알림이 없습니다" />}
        {items.map(({ alert, unread }) => {
          const info = attackInfo(alert.attackType);
          return (
            <li key={alert.id}>
              <button
                type="button"
                onClick={() => {
                  openIncident(alert.id);
                  onClose();
                }}
                className={`flex w-full gap-3 border-b border-line/60 border-l-2 px-4 py-2.5 text-left transition hover:bg-raised ${
                  SEVERITY_CLASS[alert.severity].border
                } ${unread ? "bg-raised/40" : ""}`}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-xs font-semibold text-ink">
                      {alert.attackSubtype ?? info.label} 탐지
                      <span className={`ml-2 text-[10px] ${SEVERITY_CLASS[alert.severity].text}`}>
                        {SEVERITY_META[alert.severity].label} · {alert.riskScore.toFixed(0)}점
                      </span>
                    </p>
                    {unread && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-label="읽지 않음" />}
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[11px] text-muted">
                    {alert.srcIp}
                    {alert.uniqueSrcIps > 1 && ` 외 ${alert.uniqueSrcIps - 1}`} → {endpoint(alert.destIp, alert.destPort)} ·{" "}
                    {alert.flowCount}플로우
                  </p>
                  <p className="mt-0.5 text-[10px] text-faint">
                    {fmtAgo(alert.lastSeen)}
                    {alert.active && <span className="ml-1.5 text-sev-critical">● 진행 중</span>}
                  </p>
                </div>
              </button>
            </li>
          );
        })}
      </ul>

      <div className="border-t border-line p-2">
        <button
          className="btn w-full"
          onClick={() => {
            navigate("/alerts");
            onClose();
          }}
        >
          경보 처리 화면으로 이동
        </button>
      </div>
    </div>
  );
}
