import { useMemo } from "react";
import type { Alert } from "../api/types";
import type { ThreatLevel } from "../lib/severity";
import { useLiveData } from "../store/liveData";
import { useTriage } from "../store/triage";

/** 미처리(신규/확인 중) 경보와 전체 위협 수준 계산 */
export function useThreat() {
  const { alerts, summary, connection } = useLiveData();
  const { statusOf } = useTriage();

  return useMemo(() => {
    const open: Alert[] = alerts.filter((a) => {
      const s = statusOf(a.id);
      return s === "NEW" || s === "ACK";
    });
    const newCount = alerts.filter((a) => statusOf(a.id) === "NEW").length;
    const openHigh = open.filter((a) => a.severity === "critical" || a.severity === "high").length;

    let level: ThreatLevel = "normal";
    if (!summary && (connection === "down" || connection === "connecting")) {
      level = "unknown";
    } else if (summary?.realtimeAttack || open.some((a) => a.severity === "critical" && statusOf(a.id) === "NEW")) {
      level = "severe";
    } else if (openHigh > 0) {
      level = "elevated";
    } else if (open.length > 0) {
      level = "guarded";
    }
    return { level, open, newCount, openHigh };
  }, [alerts, summary, statusOf, connection]);
}
