import type { Alert, RiskBreakdown } from "../../api/types";

/* =========================================================
   위험도 산출 근거 시각화
   1) 공격 단위: event_risk = 0.7×최대 + 0.2×평균 + 규모 보너스(최대 10)
   2) 플로우 단위: risk = base(가중합) × 유형·포트·재발 가중치 × 100
   ========================================================= */

export function EventRiskComposition({ alert }: { alert: Alert }) {
  const fromMax = 0.7 * alert.maxRisk;
  const fromAvg = 0.2 * alert.avgRisk;
  const bonus = 10 * Math.min(alert.flowCount / 100, 1);
  const parts = [
    { label: "최대 위험도 × 0.7", value: fromMax, color: "var(--c-cat-1)" },
    { label: "평균 위험도 × 0.2", value: fromAvg, color: "var(--c-cat-3)" },
    { label: `규모 보너스 (${alert.flowCount}개 플로우)`, value: bonus, color: "var(--c-cat-7)" },
  ];
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-sm bg-line/60" role="img" aria-label="위험도 구성">
        {parts.map((p) => (
          <span
            key={p.label}
            className="h-full border-r-2 border-surface last:border-r-0"
            style={{ width: `${Math.max(0, p.value)}%`, background: p.color }}
            title={`${p.label}: ${p.value.toFixed(1)}`}
          />
        ))}
      </div>
      <ul className="mt-2 space-y-1 text-[11px]">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: p.color }} />
            <span className="truncate text-muted">{p.label}</span>
            <span className="ml-auto font-mono tabular-nums text-ink">{p.value.toFixed(1)}</span>
          </li>
        ))}
      </ul>
      <p className="mt-1.5 text-[10px] text-faint">
        평균만 쓰면 긴 공격의 위험도가 묽어지므로, 가장 위험했던 순간을 중심으로 평균과 규모를 함께 반영합니다.
      </p>
    </div>
  );
}

const COMPONENT_LABEL: Record<string, string> = {
  rf: "분류 모델 (RF)",
  anomaly: "이상 탐지 (IF)",
  sequence: "시퀀스 패턴",
  ids: "IDS 심각도",
};
const COMPONENT_WEIGHT: Record<string, number> = { rf: 0.55, anomaly: 0.25, sequence: 0.1, ids: 0.1 };
const MULTIPLIER_LABEL: Record<string, string> = {
  type: "공격 유형",
  port: "포트 등급",
  recurrence: "재발 (24h)",
};
const INPUT_LABEL: Record<string, string> = {
  dest_port: "목적지 포트",
  port_grade: "포트 등급",
  recent_attacks_24h: "24시간 내 동일 출발지 공격",
  ids_severity: "IDS 심각도",
};

export function FlowRiskBreakdown({ breakdown, riskScore }: { breakdown: RiskBreakdown | null; riskScore: number }) {
  if (!breakdown) {
    return <p className="text-xs text-muted">이 분석 결과에는 산출 근거(risk_breakdown)가 기록되지 않았습니다.</p>;
  }
  const components = Object.entries(breakdown.components ?? {});
  const multipliers = Object.entries(breakdown.multipliers ?? {});
  const inputs = Object.entries(breakdown.inputs ?? {});
  const compMax = Math.max(0.0001, ...components.map(([k]) => COMPONENT_WEIGHT[k] ?? 0.0001));

  return (
    <div className="space-y-3">
      {components.length > 0 && (
        <div>
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-faint">
            기본 점수 구성 {breakdown.base !== undefined && <span className="font-mono normal-case">· base {Number(breakdown.base).toFixed(3)}</span>}
          </p>
          <ul className="space-y-1.5">
            {components.map(([k, v]) => {
              const weight = COMPONENT_WEIGHT[k];
              return (
                <li key={k} className="grid grid-cols-[96px_1fr_48px] items-center gap-2 text-[11px]">
                  <span className="truncate text-muted">{COMPONENT_LABEL[k] ?? k}</span>
                  <span className="relative h-2 rounded-sm bg-line/50">
                    {/* 가중치 상한(옅은 막대) 대비 실제 기여(진한 막대) */}
                    {weight !== undefined && (
                      <span className="absolute inset-y-0 left-0 rounded-sm bg-accent/20" style={{ width: `${(weight / compMax) * 100}%` }} />
                    )}
                    <span className="absolute inset-y-0 left-0 rounded-sm bg-accent" style={{ width: `${(Number(v) / compMax) * 100}%` }} />
                  </span>
                  <span className="text-right font-mono tabular-nums text-ink">{Number(v).toFixed(3)}</span>
                </li>
              );
            })}
          </ul>
          <p className="mt-1 text-[10px] text-faint">옅은 막대 = 항목 최대 가중치 (RF 0.55 · IF 0.25 · 시퀀스 0.10 · IDS 0.10)</p>
        </div>
      )}

      {multipliers.length > 0 && (
        <div>
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-faint">가중치</p>
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
            {breakdown.base !== undefined && <span className="rounded bg-canvas px-1.5 py-0.5 text-ink">{Number(breakdown.base).toFixed(3)}</span>}
            {multipliers.map(([k, v]) => (
              <span key={k} className="inline-flex items-center gap-1">
                <span className="text-faint">×</span>
                <span
                  className={`rounded px-1.5 py-0.5 ${Number(v) > 1 ? "bg-sev-high/15 text-ink" : "bg-canvas text-muted"}`}
                  title={MULTIPLIER_LABEL[k] ?? k}
                >
                  {Number(v).toFixed(2)} <span className="font-sans text-[10px] text-muted">{MULTIPLIER_LABEL[k] ?? k}</span>
                </span>
              </span>
            ))}
            <span className="text-faint">× 100 =</span>
            <span className="rounded bg-accent/15 px-1.5 py-0.5 font-semibold text-ink">{riskScore.toFixed(1)}</span>
          </div>
        </div>
      )}

      {inputs.length > 0 && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px]">
          {inputs.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-2">
              <dt className="text-muted">{INPUT_LABEL[k] ?? k}</dt>
              <dd className="font-mono text-ink">{String(v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
