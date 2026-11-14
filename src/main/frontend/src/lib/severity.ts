import type { Severity } from "../api/types";

/* =========================================================
   위험도(Severity) 체계
   - AI riskScore(0~100) 를 5단계로 변환
   - 경계값은 AI 파이프라인 기준과 맞춤
     · 실제 점수 분포는 30~50점대가 대부분, 극단 사례가 70~80점
     · response_playbook 의 대응 구간(40 / 70) 과 같은 눈금 사용
   ========================================================= */

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const SEVERITY_META: Record<
  Severity,
  { label: string; labelKo: string; rank: number; min: number }
> = {
  critical: { label: "Critical", labelKo: "심각", rank: 4, min: 70 },
  high: { label: "High", labelKo: "높음", rank: 3, min: 50 },
  medium: { label: "Medium", labelKo: "중간", rank: 2, min: 35 },
  low: { label: "Low", labelKo: "낮음", rank: 1, min: 0.0001 },
  info: { label: "Info", labelKo: "정보", rank: 0, min: 0 },
};

export function severityFromScore(score: number, isAttack = true): Severity {
  if (!isAttack) return "info";
  if (score >= SEVERITY_META.critical.min) return "critical";
  if (score >= SEVERITY_META.high.min) return "high";
  if (score >= SEVERITY_META.medium.min) return "medium";
  return "low";
}

/** tailwind 클래스 (정적 문자열이어야 purge 되지 않음) */
export const SEVERITY_CLASS: Record<
  Severity,
  { dot: string; text: string; chip: string; bar: string; border: string }
> = {
  critical: {
    dot: "bg-sev-critical",
    text: "text-sev-critical",
    chip: "bg-sev-critical/15 text-sev-critical ring-sev-critical/40",
    bar: "bg-sev-critical",
    border: "border-l-sev-critical",
  },
  high: {
    dot: "bg-sev-high",
    text: "text-sev-high",
    chip: "bg-sev-high/15 text-sev-high ring-sev-high/40",
    bar: "bg-sev-high",
    border: "border-l-sev-high",
  },
  medium: {
    dot: "bg-sev-medium",
    text: "text-sev-medium",
    chip: "bg-sev-medium/15 text-sev-medium ring-sev-medium/40",
    bar: "bg-sev-medium",
    border: "border-l-sev-medium",
  },
  low: {
    dot: "bg-sev-low",
    text: "text-sev-low",
    chip: "bg-sev-low/15 text-sev-low ring-sev-low/40",
    bar: "bg-sev-low",
    border: "border-l-sev-low",
  },
  info: {
    dot: "bg-sev-info",
    text: "text-sev-info",
    chip: "bg-sev-info/15 text-sev-info ring-sev-info/40",
    bar: "bg-sev-info",
    border: "border-l-sev-info",
  },
};

/** 전체 위협 수준 (상단 바 표시용) */
export type ThreatLevel = "severe" | "elevated" | "guarded" | "normal" | "unknown";

export const THREAT_META: Record<
  ThreatLevel,
  { label: string; desc: string; className: string }
> = {
  severe: {
    label: "심각",
    desc: "실시간 고위험 공격 진행 중",
    className: "bg-sev-critical/15 text-sev-critical ring-sev-critical/50",
  },
  elevated: {
    label: "경계",
    desc: "미처리 고위험 경보 존재",
    className: "bg-sev-high/15 text-sev-high ring-sev-high/50",
  },
  guarded: {
    label: "주의",
    desc: "미처리 경보 존재",
    className: "bg-sev-medium/15 text-sev-medium ring-sev-medium/50",
  },
  normal: {
    label: "정상",
    desc: "미처리 경보 없음",
    className: "bg-brand/10 text-brand ring-brand/40",
  },
  unknown: {
    label: "확인 불가",
    desc: "서버에 연결되지 않아 판단할 수 없음",
    className: "bg-sev-info/10 text-sev-info ring-sev-info/40",
  },
};
