import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Latency, LatencyStats } from "../../api/types";
import { fmtNum, fmtSec } from "../../lib/format";
import { EmptyState, Panel } from "../../components/ui";

/* =========================================================
   탐지 지연
   - 공격 탐지 시간(MTTD): 공격 시작(attack_events.first_seen) → 그 공격의 첫 AI 판정
   - 처리 지연: 연결 종료(flows.end_time) → AI 분석(ai_results.analyzed_at)
   ========================================================= */

export function LatencyTab({ d }: { d: Latency }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi label="공격 탐지 시간 (중앙값)" value={fmtSec(d.incident.p50)} sub={`공격 시작 → 첫 AI 판정 · ${fmtNum(d.incident.count)}건`} tone="brand" />
        <Kpi label="공격 탐지 시간 (90%)" value={fmtSec(d.incident.p90)} sub={`공격 10건 중 9건은 이 시간 안에 탐지 · 최대 ${fmtSec(d.incident.max)}`} />
        <Kpi label="연결 종료 → 분석 (중앙값)" value={fmtSec(d.flow.p50)} sub={`공격 판정 플로우 ${fmtNum(d.flow.count)}개 · 평균 ${fmtSec(d.flow.avg)}`} />
        <Kpi label="연결 종료 → 분석 (95%)" value={fmtSec(d.flow.p95)} sub={`최대 ${fmtSec(d.flow.max)}`} />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="공격 탐지 시간 분포" subtitle="공격이 시작된 뒤 첫 AI 판정이 나오기까지 (공격 단위)">
          <Dist stats={d.incident} color="rgb(var(--c-brand))" />
        </Panel>
        <Panel title="연결 종료 → AI 분석 분포" subtitle="Suricata 가 연결을 마감·기록한 뒤 AI 분석까지 (연결 단위)">
          <Dist stats={d.flow} color="rgb(var(--c-accent))" />
        </Panel>
      </div>

      <Panel title="지연이 생기는 구간">
        <ol className="grid gap-4 text-xs md:grid-cols-4">
          {[
            ["① 연결 마감 대기", "Suricata 는 연결이 끝나고 flow timeout 이 지나야 flow 이벤트를 기록합니다. 지연의 대부분이 여기서 생깁니다."],
            ["② 수집", "collector.py 가 eve.json 을 실시간으로 읽어 alert 와 매칭합니다."],
            ["③ AI 분석", "특징 추출 → IF·RF·시퀀스 3단계 추론 → 위험도·대응 산출 (수십 ms 수준)."],
            ["④ 공격 묶음", "attack_grouper.py 가 공격 단위로 묶어 attack_events 에 기록합니다."],
          ].map(([t, desc]) => (
            <li key={t} className="rounded-lg border border-line p-3">
              <p className="font-semibold text-ink">{t}</p>
              <p className="mt-1 leading-relaxed text-muted">{desc}</p>
            </li>
          ))}
        </ol>
        <p className="mt-3 text-[11px] leading-relaxed text-muted">
          suricata.yaml 의 <code className="rounded bg-raised px-1 font-mono">flow-timeouts</code> 를 줄이면(예: established 60초 → 10초) ①이 줄어 탐지가 빨라집니다.
          대신 긴 정상 연결이 여러 플로우로 쪼개질 수 있습니다. 이 화면으로 적용 전후를 비교할 수 있습니다.
        </p>
        {(d.incident.excluded > 0 || d.flow.excluded > 0) && (
          <p className="mt-2 rounded-md bg-sev-medium/10 px-3 py-2 text-[11px] text-ink">
            계산에서 제외: 공격 {fmtNum(d.incident.excluded)}건 · 플로우 {fmtNum(d.flow.excluded)}개 (지연이 음수이거나 1시간 초과).
            data_generator.py 로 과거 시각에 적재한 합성 데이터이거나, DB 시간대(TIMESTAMP)와 기록 시각(DATETIME)이 어긋난 경우입니다.
          </p>
        )}
      </Panel>
    </div>
  );
}

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "brand" }) {
  return (
    <div className={`panel p-4 ${tone === "brand" ? "ring-1 ring-inset ring-brand/30" : ""}`}>
      <p className="text-xs text-muted">{label}</p>
      <p className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${tone === "brand" ? "text-brand" : "text-ink"}`}>{value}</p>
      <p className="mt-0.5 text-[10px] leading-snug text-faint">{sub}</p>
    </div>
  );
}

function Dist({ stats, color }: { stats: LatencyStats; color: string }) {
  if (stats.count === 0) {
    return <EmptyState title="계산할 수 있는 데이터가 없습니다" desc="실시간 수집(collector.py)으로 탐지된 공격이 있어야 합니다." />;
  }
  return (
    <div className="h-[220px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={stats.buckets} margin={{ top: 8, right: 8, left: -4, bottom: 0 }} barCategoryGap="16%">
          <CartesianGrid stroke="rgb(var(--c-line) / 0.6)" vertical={false} />
          <XAxis dataKey="label" tickLine={false} axisLine={false} stroke="rgb(var(--c-faint))" fontSize={10} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} stroke="rgb(var(--c-faint))" fontSize={10} width={44} />
          <Tooltip
            cursor={{ fill: "rgb(var(--c-raised))" }}
            formatter={(v) => [`${Number(v).toLocaleString()}건`, "건수"]}
            contentStyle={{ background: "rgb(var(--c-surface))", border: "1px solid rgb(var(--c-line))", borderRadius: 6, fontSize: 12 }}
          />
          <Bar dataKey="count" fill={color} radius={[4, 4, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
