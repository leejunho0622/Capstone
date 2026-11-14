import { ShieldCheck, Sparkles } from "lucide-react";
import type { IdsComparison } from "../../api/types";
import { useUi } from "../../store/ui";
import { attackInfo } from "../../lib/attackTypes";
import { SEVERITY_CLASS } from "../../lib/severity";
import { endpoint, fmtNum, fmtSmart } from "../../lib/format";
import { DirectionBadge, EmptyState, IpText, Panel, SeverityBadge } from "../../components/ui";

/* =========================================================
   IDS 룰 탐지 vs AI 탐지
   - IDS 탐지: flows.severity 가 있음 (Suricata 룰이 alert 를 냄)
   - AI 탐지 : ai_results.attack_type <> 'Normal'
   ========================================================= */

const pct = (a: number, b: number) => (b ? `${((a / b) * 100).toFixed(1)}%` : "-");

export function IdsComparisonTab({ d }: { d: IdsComparison }) {
  const { openIncident, openFlow } = useUi();
  const m = d.flows;
  const analyzed = m.both + m.aiOnly + m.idsOnly + m.neither;
  const aiDetected = m.both + m.aiOnly;
  const types = d.types.filter((t) => t.aiFlows > 0 || t.incidents > 0);

  return (
    <div className="space-y-5">
      {/* ---- 핵심 수치 ---- */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Headline
          tone="brand"
          label="IDS 룰이 놓친 공격을 AI가 탐지"
          value={fmtNum(d.incidents.aiOnly)}
          unit={`/ ${fmtNum(d.incidents.total)}건`}
          sub={`공격의 ${pct(d.incidents.aiOnly, d.incidents.total)} 는 Suricata 룰 alert 없이 AI 만 탐지`}
        />
        <Headline
          label="IDS 룰도 탐지한 공격"
          value={fmtNum(d.incidents.idsDetected)}
          unit={`/ ${fmtNum(d.incidents.total)}건`}
          sub="공격에 묶인 플로우 중 하나라도 룰 alert 가 있음"
        />
        <Headline
          label="AI가 추가로 잡은 플로우"
          value={fmtNum(m.aiOnly)}
          unit="개"
          sub={`AI 탐지 플로우의 ${pct(m.aiOnly, aiDetected)} 는 룰 alert 없음`}
        />
        <Headline
          tone="high"
          label="AI 미탐 후보 (룰만 탐지)"
          value={fmtNum(m.idsOnly)}
          unit="개"
          sub="룰은 alert 를 냈지만 AI 는 정상으로 판정 · 아래 목록에서 확인"
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-5">
        {/* ---- 2×2 교차표 ---- */}
        <Panel className="xl:col-span-2" title="플로우 단위 교차표" subtitle={`AI 분석을 거친 플로우 ${fmtNum(analyzed)}개 기준`}>
          <div className="grid grid-cols-[4.5rem_1fr_1fr] gap-3 text-xs">
            <span />
            <span className="pb-1 text-center font-semibold text-muted">AI 공격 판정</span>
            <span className="pb-1 text-center font-semibold text-muted">AI 정상 판정</span>

            <RowHead top="IDS 룰" bottom="alert 있음" />
            <Cell n={m.both} total={analyzed} title="둘 다 탐지" desc="룰과 AI 가 모두 공격으로 봄" cls="bg-accent/10 ring-accent/30" />
            <Cell n={m.idsOnly} total={analyzed} title="룰만 탐지" desc="AI 미탐 후보 · 검토 필요" cls="bg-sev-high/10 ring-sev-high/30" />

            <RowHead top="IDS 룰" bottom="alert 없음" />
            <Cell n={m.aiOnly} total={analyzed} title="AI만 탐지" desc="룰 기반 IDS 가 놓친 연결" cls="bg-brand/10 ring-brand/40" emphasize />
            <Cell n={m.neither} total={analyzed} title="둘 다 정상" desc="정상 트래픽" cls="bg-raised ring-line" />
          </div>
          <p className="mt-3 text-[10px] leading-relaxed text-faint">
            Suricata 룰(시그니처)은 알려진 패턴과 일치할 때만 alert 를 냅니다. AI 는 연결의 행동 특징(패킷 수·플래그·시퀀스)으로 판단하므로
            룰에 없는 정찰·무차별 대입·C2 비콘을 잡을 수 있습니다.
          </p>
        </Panel>

        {/* ---- 유형별 ---- */}
        <Panel className="xl:col-span-3" title="공격 유형별 비교" subtitle="막대: AI 탐지 플로우 중 룰도 탐지(파랑) / AI만 탐지(초록)" bodyClassName="p-0">
          {types.length === 0 ? (
            <EmptyState title="해당 기간의 공격 판정이 없습니다" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px]">
                <thead>
                  <tr>
                    <th className="th">유형</th>
                    <th className="th text-right">AI 탐지 플로우</th>
                    <th className="th w-[34%]">룰 탐지 비율</th>
                    <th className="th text-right">공격</th>
                    <th className="th text-right">AI만 탐지한 공격</th>
                  </tr>
                </thead>
                <tbody>
                  {types.map((t) => {
                    const info = attackInfo(t.type);
                    const idsShare = t.aiFlows ? t.idsAlsoFlows / t.aiFlows : 0;
                    const aiOnlyInc = t.incidents - t.idsDetectedIncidents;
                    return (
                      <tr key={t.type} className="hover:bg-raised">
                        <td className="td">
                          <span className="inline-flex items-center gap-1.5">
                            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: info.color }} />
                            {info.label}
                          </span>
                        </td>
                        <td className="td text-right font-mono">{fmtNum(t.aiFlows)}</td>
                        <td className="td">
                          {t.aiFlows ? (
                            <span className="flex items-center gap-2">
                              <span className="flex h-2.5 flex-1 overflow-hidden rounded-sm bg-line/50">
                                <span className="bg-accent" style={{ width: `${idsShare * 100}%` }} />
                                <span className="bg-brand" style={{ width: `${(1 - idsShare) * 100}%` }} />
                              </span>
                              <span className="w-12 text-right font-mono text-[11px] text-muted">{(idsShare * 100).toFixed(0)}%</span>
                            </span>
                          ) : (
                            <span className="text-faint">-</span>
                          )}
                        </td>
                        <td className="td text-right font-mono">{fmtNum(t.incidents)}</td>
                        <td className={`td text-right font-mono ${aiOnlyInc > 0 ? "font-semibold text-brand" : "text-muted"}`}>
                          {t.incidents ? `${fmtNum(aiOnlyInc)} (${pct(aiOnlyInc, t.incidents)})` : "-"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      {/* ---- 사례 ---- */}
      <div className="grid gap-5 2xl:grid-cols-2">
        <Panel
          title={
            <span className="inline-flex items-center gap-1.5">
              <Sparkles size={14} className="text-brand" /> AI만 탐지한 공격 (위험도 순)
            </span>
          }
          subtitle="공격에 묶인 플로우 어디에도 Suricata 룰 alert 가 없었던 공격 · 누르면 상세"
          bodyClassName="p-0"
        >
          {d.aiOnlyIncidents.length === 0 ? (
            <EmptyState title="없음" desc="모든 공격에서 룰 alert 가 함께 발생했습니다." />
          ) : (
            <ul className="divide-y divide-line/60">
              {d.aiOnlyIncidents.map((a) => (
                <li key={a.id}>
                  <button className="flex w-full items-center gap-3 px-4 py-2 text-left text-xs hover:bg-raised" onClick={() => openIncident(a.id)}>
                    <SeverityBadge severity={a.severity} compact />
                    <span className="w-36 shrink-0 truncate font-medium">{a.attackSubtype ?? attackInfo(a.attackType).label}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-muted">
                      {a.srcIp} → {endpoint(a.destIp, a.destPort)}
                    </span>
                    <DirectionBadge src={a.srcIp} dst={a.destIp} compact />
                    <span className="w-24 shrink-0 whitespace-nowrap text-right font-mono text-muted">{fmtSmart(a.firstSeen)}</span>
                    <span className={`w-10 text-right font-mono ${SEVERITY_CLASS[a.severity].text}`}>{a.riskScore.toFixed(0)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title={
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck size={14} className="text-sev-high" /> 룰만 탐지한 플로우 (AI 미탐 후보)
            </span>
          }
          subtitle="룰 alert 는 있었지만 AI 가 정상으로 본 연결 · 오탐 룰인지 AI 미탐인지 검토 대상"
          bodyClassName="p-0"
        >
          {d.idsOnlyFlows.length === 0 ? (
            <EmptyState title="없음" desc="룰이 alert 를 낸 연결은 모두 AI 도 공격으로 판정했습니다." />
          ) : (
            <ul className="divide-y divide-line/60">
              {d.idsOnlyFlows.map(({ flow }) => (
                <li key={flow.flowId}>
                  <button className="flex w-full items-center gap-3 px-4 py-2 text-left text-xs hover:bg-raised" onClick={() => openFlow(flow.flowId)}>
                    <span className="w-24 shrink-0 whitespace-nowrap font-mono text-muted">{fmtSmart(flow.startTime)}</span>
                    <span className="min-w-0 flex-1 truncate">
                      <IpText ip={flow.srcIp} port={flow.srcPort} /> <span className="text-faint">→</span>{" "}
                      <IpText ip={flow.destIp} port={flow.destPort} />
                    </span>
                    <span className="text-muted">{flow.protocol}</span>
                    <span className="font-mono text-[10px] text-accent">#{flow.flowId}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Headline({
  label,
  value,
  unit,
  sub,
  tone,
}: {
  label: string;
  value: string;
  unit?: string;
  sub: string;
  tone?: "brand" | "high";
}) {
  return (
    <div className={`panel p-4 ${tone === "brand" ? "ring-1 ring-inset ring-brand/30" : ""}`}>
      <p className="text-xs text-muted">{label}</p>
      <p
        className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
          tone === "brand" ? "text-brand" : tone === "high" ? "text-sev-high" : "text-ink"
        }`}
      >
        {value}
        {unit && <span className="ml-1 font-sans text-xs font-normal text-muted">{unit}</span>}
      </p>
      <p className="mt-0.5 text-[10px] leading-snug text-faint">{sub}</p>
    </div>
  );
}

function Cell({
  n,
  total,
  title,
  desc,
  cls,
  emphasize = false,
}: {
  n: number;
  total: number;
  title: string;
  desc: string;
  cls: string;
  emphasize?: boolean;
}) {
  return (
    <div className={`rounded-lg p-3 ring-1 ring-inset ${cls}`}>
      <p className={`text-[11px] font-semibold ${emphasize ? "text-brand" : "text-ink"}`}>{title}</p>
      <p className="mt-1 font-mono text-xl font-semibold tabular-nums text-ink">{fmtNum(n)}</p>
      <p className="text-[11px] font-medium text-muted">{pct(n, total)}</p>
      <p className="mt-0.5 text-[10px] leading-snug text-faint">{desc}</p>
    </div>
  );
}

function RowHead({ top, bottom }: { top: string; bottom: string }) {
  return (
    <span className="flex flex-col items-end justify-center pr-1 text-right text-[11px] font-semibold leading-tight text-muted">
      <span>{top}</span>
      <span>{bottom}</span>
    </span>
  );
}
