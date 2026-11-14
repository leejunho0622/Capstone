import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { BrainCircuit, Download, RefreshCw } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { falsePositiveCsvUrl, getAiQuality, getIdsComparison, getLatency } from "../api/client";
import type { AiQuality } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useSettings } from "../store/settings";
import { attackInfo } from "../lib/attackTypes";
import { fmtNum } from "../lib/format";
import { EmptyState, Panel, Segmented, Skeleton, Spinner } from "../components/ui";
import { IdsComparisonTab } from "./ai/IdsComparisonTab";
import { LatencyTab } from "./ai/LatencyTab";

/* =========================================================
   AI 성능 분석 (탭 3개, ?tab=)
   - quality : 유형별 판정·신뢰도/위험도 분포·관제요원 정탐/오탐, 재학습용 오탐 CSV
   - ids     : Suricata 룰(시그니처) 탐지 대비 AI 탐지 — AI 가 추가로 잡은 공격
   - latency : 공격 시작 → AI 판정까지 걸린 시간(MTTD), 연결 종료 → 분석 지연
   ========================================================= */

type DaysKey = "1" | "7" | "14" | "30";
type TabKey = "quality" | "ids" | "latency";

const TABS: Array<{ value: TabKey; label: string; desc: string }> = [
  { value: "quality", label: "판정 품질", desc: "AI 판정 결과와 관제요원이 확정한 정탐·오탐을 함께 봅니다." },
  { value: "ids", label: "IDS 룰 대비", desc: "Suricata 룰 alert 와 AI 판정을 같은 트래픽에서 비교합니다." },
  { value: "latency", label: "탐지 지연", desc: "공격이 시작된 뒤 AI 가 판정하기까지 걸린 시간입니다." },
];

export default function AiQualityPage() {
  const [params, setParams] = useSearchParams();
  const { settings } = useSettings();
  const days = (params.get("days") ?? "7") as DaysKey;
  const tabParam = params.get("tab");
  const tab: TabKey = tabParam === "ids" || tabParam === "latency" ? tabParam : "quality";
  const meta = TABS.find((t) => t.value === tab)!;

  const setParam = (key: "days" | "tab", value: string, def: string) => {
    const next = new URLSearchParams(params);
    if (value === def) next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  return (
    <div className="mx-auto max-w-[1880px] space-y-5 p-4 lg:p-5">
      <div className="panel flex flex-wrap items-center gap-3 p-3">
        <div className="mr-auto flex min-w-0 items-center gap-2.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-brand/10 text-brand">
            <BrainCircuit size={16} />
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold">AI 성능 분석</p>
            <p className="truncate text-[11px] text-muted">{meta.desc}</p>
          </div>
        </div>
        <Segmented label="보기" value={tab} onChange={(v) => setParam("tab", v, "quality")} options={TABS} />
        <Segmented
          label="기간"
          value={days}
          onChange={(v) => setParam("days", v, "7")}
          options={[
            { value: "1", label: "오늘" },
            { value: "7", label: "7일" },
            { value: "14", label: "14일" },
            { value: "30", label: "30일" },
          ]}
        />
        {tab === "quality" && (
          <a className="btn btn-primary" href={falsePositiveCsvUrl(Math.max(30, Number(days)))} download>
            <Download size={13} /> 재학습용 오탐 데이터 (CSV)
          </a>
        )}
      </div>

      {tab === "quality" && <TabLoader key="q" days={days} paused={settings.paused} load={getAiQuality} render={(d) => <QualityBody q={d} />} />}
      {tab === "ids" && <TabLoader key="i" days={days} paused={settings.paused} load={getIdsComparison} render={(d) => <IdsComparisonTab d={d} />} />}
      {tab === "latency" && <TabLoader key="l" days={days} paused={settings.paused} load={getLatency} render={(d) => <LatencyTab d={d} />} />}
    </div>
  );
}

/** 탭마다 자기 API 만 폴링 (보이지 않는 탭은 요청하지 않음) */
function TabLoader<T>({
  days,
  paused,
  load,
  render,
}: {
  days: string;
  paused: boolean;
  load: (days: number, signal: AbortSignal) => Promise<T>;
  render: (d: T) => ReactNode;
}) {
  const { data, error, loading, refresh } = usePolling((signal) => load(Number(days), signal), [days], {
    intervalMs: 60_000,
    enabled: !paused,
  });
  if (error && !data) {
    return (
      <div className="panel">
        <EmptyState title="지표를 불러오지 못했습니다" desc={error.message} />
        <div className="flex justify-center pb-6">
          <button className="btn" onClick={refresh}>
            <RefreshCw size={13} /> 다시 시도
          </button>
        </div>
      </div>
    );
  }
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="relative space-y-5">
      {loading && (
        <span className="absolute -top-3 right-1 z-10">
          <Spinner size={12} />
        </span>
      )}
      {render(data)}
    </div>
  );
}

function QualityBody({ q }: { q: AiQuality }) {
  const attackRatio = q.analyzedFlows ? q.attackFlows / q.analyzedFlows : 0;
  const fpRate = q.reviewedIncidents ? q.falsePositiveIncidents / q.reviewedIncidents : null;
  const attackTypes = q.types.filter((t) => t.type !== "Normal");
  const maxFlows = Math.max(1, ...attackTypes.map((t) => t.flows));

  return (
    <>
      {/* ---- KPI ---- */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Kpi label="분석한 플로우" value={fmtNum(q.analyzedFlows)} sub={`최근 ${q.days}일`} />
        <Kpi label="공격 판정" value={fmtNum(q.attackFlows)} sub={`전체의 ${(attackRatio * 100).toFixed(1)}%`} />
        <Kpi
          label="공격 판정 평균 신뢰도"
          value={`${(q.avgAttackConfidence * 100).toFixed(1)}%`}
          sub="RandomForest 최대 클래스 확률"
        />
        <Kpi
          label="관제요원 확인 오탐률"
          value={fpRate === null ? "-" : `${(fpRate * 100).toFixed(1)}%`}
          sub={`처리 확정 ${fmtNum(q.reviewedIncidents)}건 중 오탐 ${fmtNum(q.falsePositiveIncidents)}건`}
          tone={fpRate !== null && fpRate >= 0.2 ? "high" : undefined}
        />
        <Kpi
          label="재학습 데이터"
          value={fmtNum(q.falsePositiveFlows)}
          sub="오탐으로 표시된 플로우 (feature_vector 포함)"
          tone="brand"
        />
      </div>

      {/* ---- 유형별 ---- */}
      <Panel title="공격 유형별 판정 품질" subtitle="경보 처리 막대: 조치 완료(정탐) · 오탐 · 확인 중 · 미처리" bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[960px]">
            <thead>
              <tr>
                <th className="th">유형</th>
                <th className="th">분석 플로우</th>
                <th className="th">평균 신뢰도</th>
                <th className="th text-right">평균 위험도</th>
                <th className="th text-right">경보</th>
                <th className="th w-[30%]">관제요원 처리 결과</th>
                <th className="th text-right">오탐률</th>
              </tr>
            </thead>
            <tbody>
              {attackTypes.map((t) => {
                const decided = t.resolved + t.falsePositive;
                const rate = decided ? t.falsePositive / decided : null;
                const info = attackInfo(t.type);
                return (
                  <tr key={t.type} className="hover:bg-raised">
                    <td className="td">
                      <span className="inline-flex items-center gap-1.5">
                        <span className="h-2.5 w-2.5 rounded-sm" style={{ background: info.color }} />
                        <span className="font-medium">{info.label}</span>
                        <span className="text-[10px] text-faint">{info.labelKo}</span>
                      </span>
                    </td>
                    <td className="td">
                      <span className="flex items-center gap-2">
                        <span className="w-14 text-right font-mono tabular-nums">{fmtNum(t.flows)}</span>
                        <span className="h-1.5 w-24 overflow-hidden rounded-full bg-line/70">
                          <span className="block h-full rounded-full bg-accent/70" style={{ width: `${(t.flows / maxFlows) * 100}%` }} />
                        </span>
                      </span>
                    </td>
                    <td className="td">
                      {t.flows ? (
                        <span className="flex items-center gap-2">
                          <span className="w-12 text-right font-mono tabular-nums">{(t.avgConfidence * 100).toFixed(1)}%</span>
                          <span className="h-1.5 w-20 overflow-hidden rounded-full bg-line/70">
                            <span className="block h-full rounded-full bg-brand" style={{ width: `${t.avgConfidence * 100}%` }} />
                          </span>
                        </span>
                      ) : (
                        <span className="text-faint">-</span>
                      )}
                    </td>
                    <td className="td text-right font-mono">{t.flows ? t.avgRisk.toFixed(1) : "-"}</td>
                    <td className="td text-right font-mono">{fmtNum(t.incidents)}</td>
                    <td className="td">
                      <OutcomeBar t={t} />
                    </td>
                    <td className={`td text-right font-mono ${rate !== null && rate >= 0.2 ? "font-semibold text-sev-high" : ""}`}>
                      {rate === null ? <span className="text-faint">-</span> : `${(rate * 100).toFixed(1)}%`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="border-t border-line px-4 py-2 text-[10px] text-faint">
          오탐률 = 오탐 ÷ (조치 완료 + 오탐). 관제요원이 아직 판정하지 않은 경보(확인 중·미처리)는 계산에서 뺍니다.
        </p>
      </Panel>

      {/* ---- 분포 ---- */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="공격 판정 신뢰도 분포" subtitle="낮은 신뢰도 구간에 몰려 있으면 모델이 확신하지 못하는 판정이 많다는 뜻">
          <Histogram data={q.confidenceHistogram.map((b) => ({ label: `${Math.round(b.from * 100)}`, count: b.count }))} unit="%" color="rgb(var(--c-brand))" />
        </Panel>
        <Panel title="공격 판정 위험도 분포" subtitle="10점 단위 · 색은 위험도 등급">
          <Histogram
            data={q.riskHistogram.map((b) => ({ label: `${b.from}`, count: b.count }))}
            unit="점"
            colorAt={(i) =>
              i >= 7 ? "rgb(var(--c-sev-critical))" : i >= 5 ? "rgb(var(--c-sev-high))" : i >= 3.5 ? "rgb(var(--c-sev-medium))" : "rgb(var(--c-sev-low))"
            }
          />
        </Panel>
      </div>

      {/* ---- 모델 + 피드백 루프 ---- */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="사용 중인 모델" subtitle="ai_results.model_name / model_version">
          {q.models.length === 0 ? (
            <EmptyState title="분석 기록이 없습니다" />
          ) : (
            <ul className="divide-y divide-line/60">
              {q.models.map((m) => (
                <li key={`${m.modelName}-${m.modelVersion}`} className="flex items-center justify-between py-2 text-xs">
                  <span>
                    <span className="font-medium">{m.modelName}</span>{" "}
                    <span className="rounded bg-raised px-1.5 py-0.5 font-mono text-[10px] text-muted">{m.modelVersion}</span>
                  </span>
                  <span className="font-mono tabular-nums">{fmtNum(m.flows)} 플로우</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="오탐 피드백 → 재학습 흐름">
          <ol className="space-y-2 text-xs">
            {[
              ["경보 처리", "관제요원이 경보를 '오탐'으로 처리"],
              ["자동 표시", "그 공격에 묶인 플로우의 ai_results.is_false_positive = true"],
              ["데이터 수집", "위 'CSV' 버튼 → 플로우별 feature_vector(14개 특징값) + 보정 라벨 Normal"],
              ["재학습", "trainer.py 학습 데이터에 추가해 같은 패턴의 오탐을 줄임"],
            ].map(([title, desc], i) => (
              <li key={title} className="flex gap-3">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand/15 font-mono text-[10px] font-bold text-brand">
                  {i + 1}
                </span>
                <span>
                  <b className="text-ink">{title}</b> <span className="text-muted">· {desc}</span>
                </span>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </>
  );
}

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "high" | "brand" }) {
  return (
    <div className="panel p-4">
      <p className="text-xs text-muted">{label}</p>
      <p
        className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
          tone === "high" ? "text-sev-high" : tone === "brand" ? "text-brand" : "text-ink"
        }`}
      >
        {value}
      </p>
      <p className="mt-0.5 truncate text-[10px] text-faint" title={sub}>
        {sub}
      </p>
    </div>
  );
}

function OutcomeBar({ t }: { t: AiQuality["types"][number] }) {
  const parts = [
    { key: "조치 완료", v: t.resolved, cls: "bg-sev-low" },
    { key: "오탐", v: t.falsePositive, cls: "bg-faint" },
    { key: "확인 중", v: t.inProgress, cls: "bg-sev-medium" },
    { key: "미처리", v: t.untouched, cls: "bg-line" },
  ];
  const total = parts.reduce((s, p) => s + p.v, 0);
  if (total === 0) return <span className="text-[11px] text-faint">경보 없음</span>;
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-sm bg-line/50">
        {parts.map((p) =>
          p.v > 0 ? (
            <span
              key={p.key}
              className={`${p.cls} border-r-2 border-surface last:border-r-0`}
              style={{ width: `${(p.v / total) * 100}%` }}
              title={`${p.key} ${p.v}건`}
            />
          ) : null
        )}
      </div>
      <p className="mt-1 text-[10px] text-muted">
        정탐 <b className="text-ink">{t.resolved}</b> · 오탐 <b className="text-ink">{t.falsePositive}</b> · 확인 중 {t.inProgress} · 미처리 {t.untouched}
      </p>
    </div>
  );
}

function Histogram({
  data,
  unit,
  color,
  colorAt,
}: {
  data: Array<{ label: string; count: number }>;
  unit: string;
  color?: string;
  colorAt?: (i: number) => string;
}) {
  if (data.every((d) => d.count === 0)) return <EmptyState title="해당 기간의 공격 판정이 없습니다" />;
  return (
    <div className="h-[200px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -4, bottom: 0 }} barCategoryGap="12%">
          <CartesianGrid stroke="rgb(var(--c-line) / 0.6)" vertical={false} />
          <XAxis dataKey="label" tickLine={false} axisLine={false} stroke="rgb(var(--c-faint))" fontSize={10} unit={unit} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} stroke="rgb(var(--c-faint))" fontSize={10} width={44} />
          <Tooltip
            cursor={{ fill: "rgb(var(--c-raised))" }}
            formatter={(v) => [`${Number(v).toLocaleString()}건`, "판정 수"]}
            labelFormatter={(l) => `${l}${unit} 이상`}
            contentStyle={{ background: "rgb(var(--c-surface))", border: "1px solid rgb(var(--c-line))", borderRadius: 6, fontSize: 12 }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
            {data.map((d, i) => (
              <Cell key={d.label} fill={colorAt ? colorAt(i) : color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
