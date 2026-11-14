import { useEffect, useRef, useState } from "react";
import { Check, Eye, ShieldAlert, Volume2, X } from "lucide-react";
import type { Alert } from "../api/types";
import { useLiveData } from "../store/liveData";
import { useSettings } from "../store/settings";
import { useTriage } from "../store/triage";
import { useUi } from "../store/ui";
import { SEVERITY_META } from "../lib/severity";
import { attackInfo } from "../lib/attackTypes";
import { endpoint } from "../lib/format";
import { actionLabel } from "../lib/actions";
import { playAlarm, speak, stopSpeaking } from "../lib/alertAudio";

/* =========================================================
   고위험 경보 알림 (시각 + 청각, 접근성 기능)
   - 새로 들어온 경보 중 '설정한 등급 이상' + '신규' 인 것만 울림
   - 첫 화면 진입 시에는 최근 5분 이내 미처리 경보만 알림
   - 같은 경보로 두 번 울리지 않음
   ========================================================= */

const RECENT_MS = 5 * 60 * 1000;
const FLASH_MS = 6000;

function voiceText(a: Alert) {
  const info = attackInfo(a.attackType);
  const src = a.uniqueSrcIps > 1 ? `${a.srcIp} 등 ${a.uniqueSrcIps}개 출발지` : a.srcIp;
  return `${SEVERITY_META[a.severity].labelKo} 경보. ${info.labelKo} 공격이 탐지되었습니다. 위험 점수 ${Math.round(
    a.riskScore
  )}점. 출발지 ${src}. 대상 ${a.destIp}${a.destPort ? ` 포트 ${a.destPort}` : ""}.`;
}

export function CriticalAlarm() {
  const { alerts, freshIds, isInitialLoad } = useLiveData();
  const { settings } = useSettings();
  const { statusOf, setStatus } = useTriage();
  const { openIncident, toast } = useUi();
  const [current, setCurrent] = useState<{ alert: Alert; extra: number } | null>(null);
  const [flashing, setFlashing] = useState(false);
  const notified = useRef(new Set<string>());

  const settingsRef = useRef(settings);
  useEffect(() => {
    settingsRef.current = settings;
  });

  useEffect(() => {
    if (alerts.length === 0) return;
    const s = settingsRef.current;
    const minRank = SEVERITY_META[s.alarmSeverity].rank;
    const now = Date.now();

    const candidates = alerts
      .filter((a) => SEVERITY_META[a.severity].rank >= minRank)
      .filter((a) => statusOf(a.id) === "NEW")
      .filter((a) => !notified.current.has(a.id))
      .filter((a) =>
        isInitialLoad ? now - (a.lastSeen?.getTime() ?? 0) < RECENT_MS : freshIds.has(a.id)
      )
      .sort((a, b) => b.riskScore - a.riskScore);

    if (candidates.length === 0) return;
    candidates.forEach((a) => notified.current.add(a.id));
    const top = candidates[0];

    setCurrent({ alert: top, extra: candidates.length - 1 });

    let flashTimer: number | undefined;
    if (s.visualAlarm) {
      setFlashing(true);
      flashTimer = window.setTimeout(() => setFlashing(false), FLASH_MS);
    }
    try {
      if (s.soundAlarm) playAlarm(s.volume);
      if (s.voiceAlarm) window.setTimeout(() => speak(voiceText(top), s.volume), s.soundAlarm ? 1100 : 0);
    } catch (err) {
      console.error("경보음 재생 실패", err);
    }
    if (!s.visualAlarm) {
      toast(`${attackInfo(top.attackType).label} 경보 (${top.srcIp})`, "error");
    }
    return () => window.clearTimeout(flashTimer);
    // statusOf 는 매번 새 함수이므로 의도적으로 제외
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts, freshIds, isInitialLoad, toast]);

  const close = () => {
    setCurrent(null);
    setFlashing(false);
    stopSpeaking();
  };

  if (!current || !settings.visualAlarm) return null;
  const { alert, extra } = current;
  const info = attackInfo(alert.attackType);

  return (
    <>
      {flashing && (
        <div
          className="pointer-events-none fixed inset-0 z-[60] animate-screen-flash bg-sev-critical"
          aria-hidden
        />
      )}
      <section
        role="alert"
        aria-live="assertive"
        className="fixed bottom-5 left-1/2 z-[70] w-[min(760px,calc(100%-2rem))] -translate-x-1/2 animate-alert-pulse overflow-hidden rounded-xl border-2 border-sev-critical bg-surface shadow-2xl"
      >
        <div className="flex items-center gap-2 bg-sev-critical px-4 py-1.5 text-xs font-bold text-white">
          <ShieldAlert size={14} />
          {SEVERITY_META[alert.severity].label.toUpperCase()} 경보 · 즉시 확인 필요
          {extra > 0 && <span className="ml-auto rounded bg-black/25 px-1.5">외 {extra}건</span>}
        </div>
        <div className="flex flex-col gap-4 p-4 md:flex-row md:items-center">
          <div className="min-w-0 flex-1">
            <p className="text-lg font-bold text-ink">
              {alert.attackSubtype ?? info.label} <span className="text-sm font-medium text-muted">{info.labelKo}</span>
              {info.mitre && <span className="ml-2 font-mono text-xs text-muted">{info.mitre.id}</span>}
            </p>
            <p className="mt-1 font-mono text-sm text-ink">
              {alert.srcIp}
              {alert.uniqueSrcIps > 1 && <span className="text-muted"> 외 {alert.uniqueSrcIps - 1}개</span>} →{" "}
              {endpoint(alert.destIp, alert.destPort)}
            </p>
            <p className="mt-2 text-xs text-muted">
              위험 점수 <b className="font-mono text-sev-critical">{alert.riskScore.toFixed(0)}</b>
              {" · "}플로우 {alert.flowCount}개
              {alert.action !== "-" && <> · 권장 조치: <b className="text-ink">{actionLabel(alert.action)}</b></>}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2 md:flex-col">
            <button
              className="btn btn-primary h-9"
              onClick={() => {
                openIncident(alert.id);
                close();
              }}
            >
              <Eye size={14} /> 상세 보기
            </button>
            <button
              className="btn h-9"
              onClick={async () => {
                try {
                  await setStatus([alert.id], "ACK");
                  toast("확인 중으로 변경했습니다", "success");
                } catch {
                  toast("상태 저장에 실패했습니다", "error");
                }
                close();
              }}
            >
              <Check size={14} /> 확인 처리
            </button>
            <div className="flex gap-2">
              <button
                className="btn h-9 flex-1"
                onClick={() => speak(voiceText(alert), settings.volume)}
                title="음성 안내 다시 듣기"
                aria-label="음성 안내 다시 듣기"
              >
                <Volume2 size={14} />
              </button>
              <button className="btn h-9 flex-1" onClick={close} title="닫기" aria-label="닫기">
                <X size={14} />
              </button>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
