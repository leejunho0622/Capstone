import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRight, GitBranch, Radio, Search, TrendingUp, X } from "lucide-react";
import { getChains } from "../api/client";
import type { Chain } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useSettings } from "../store/settings";
import { useUi } from "../store/ui";
import { STAGES, STAGE_LABEL, stageOf, type StageKey } from "../lib/killchain";
import { attackInfo } from "../lib/attackTypes";
import { SEVERITY_CLASS, severityFromScore } from "../lib/severity";
import { endpoint, fmtAgo, fmtDateTime, fmtDuration, fmtNum, fmtSmart, isPrivateIp } from "../lib/format";
import { DirectionBadge, EmptyState, Panel, Segmented, SeverityBadge, Skeleton, Spinner } from "../components/ui";

/* =========================================================
   공격 연관 분석
   같은 출발지에서 이어진 공격(attack_events)을 킬체인 단계로 연결해 보여줌
   예) PortScan(정찰) → BruteForce-SSH(자격 증명 접근) → C2Beacon(명령 및 제어)
   ========================================================= */

type HoursKey = "6" | "24" | "72" | "168";
type GapKey = "10" | "30" | "60";

export default function ChainsPage() {
  const [params, setParams] = useSearchParams();
  const { settings } = useSettings();
  const hours = (params.get("hours") ?? "24") as HoursKey;
  const gap = (params.get("gap") ?? "30") as GapKey;
  const onlyEscalated = params.get("escalated") === "1";
  const src = params.get("src") ?? "";

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  const { data, error, loading } = usePolling(
    (signal) => getChains({ hours: Number(hours), gap: Number(gap) }, signal),
    [hours, gap],
    { intervalMs: Math.max(10_000, settings.pollMs * 2), enabled: !settings.paused }
  );

  const chains = useMemo(
    () =>
      (data ?? []).filter(
        (c) => (!onlyEscalated || c.escalated) && (!src || c.srcIp.startsWith(src.trim()))
      ),
    [data, onlyEscalated, src]
  );

  const stats = useMemo(() => {
    const all = data ?? [];
    return {
      total: all.length,
      escalated: all.filter((c) => c.escalated).length,
      active: all.filter((c) => c.active).length,
      reachedControl: all.filter((c) => c.stages.includes("CONTROL") || c.stages.includes("IMPACT")).length,
    };
  }, [data]);

  return (
    <div className="mx-auto max-w-[1880px] space-y-4 p-4 lg:p-5">
      {/* ---- 설명 + 조건 ---- */}
      <div className="panel flex flex-wrap items-center gap-3 p-3">
        <div className="mr-auto flex min-w-0 items-center gap-2.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent">
            <GitBranch size={16} />
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold">공격 연관 분석</p>
            <p className="truncate text-[11px] text-muted">
              같은 출발지에서 {gap}분 안에 이어진 공격을 하나의 흐름으로 묶고, MITRE ATT&CK 전술 기준 정찰 → 자격 증명 접근 → 명령 및 제어(C2) → 영향(서비스 거부) 순서로 진행했는지 봅니다.
            </p>
          </div>
        </div>
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <input
            className="input w-44 pl-7 font-mono"
            placeholder="출발지 IP"
            value={src}
            onChange={(e) => set("src", e.target.value)}
            aria-label="출발지 IP 검색"
          />
        </div>
        <Segmented
          label="조회 기간"
          value={hours}
          onChange={(v) => set("hours", v === "24" ? "" : v)}
          options={[
            { value: "6", label: "6시간" },
            { value: "24", label: "24시간" },
            { value: "72", label: "3일" },
            { value: "168", label: "7일" },
          ]}
        />
        <Segmented
          label="묶음 간격"
          value={gap}
          onChange={(v) => set("gap", v === "30" ? "" : v)}
          options={[
            { value: "10", label: "10분" },
            { value: "30", label: "30분" },
            { value: "60", label: "60분" },
          ]}
        />
        <label className="flex items-center gap-1.5 text-xs text-muted">
          <input
            type="checkbox"
            checked={onlyEscalated}
            onChange={(e) => set("escalated", e.target.checked ? "1" : "")}
            className="accent-[rgb(var(--c-accent))]"
          />
          단계가 진행된 체인만
        </label>
        {(src || onlyEscalated) && (
          <button className="btn btn-ghost" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            <X size={13} /> 초기화
          </button>
        )}
      </div>

      {/* ---- 요약 ---- */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="공격 체인" value={stats.total} hint={`최근 ${hours}시간, 공격 2건 이상`} />
        <Stat label="단계 진행" value={stats.escalated} hint="앞 단계 → 뒤 단계로 넘어간 체인" tone={stats.escalated ? "high" : undefined} />
        <Stat label="C2·영향 단계 도달" value={stats.reachedControl} hint="C2 또는 영향(서비스 거부) 단계까지 간 체인" tone={stats.reachedControl ? "critical" : undefined} />
        <Stat label="진행 중" value={stats.active} hint="아직 끝나지 않은 공격이 포함된 체인" />
      </div>

      {/* ---- 단계 범례 ---- */}
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted">
        {STAGES.map((s, i) => (
          <span key={s.key} className="flex items-center gap-2">
            <span className="rounded-md border border-line bg-surface px-2 py-1">
              <b className="text-ink">{i + 1}. {s.label}</b> <span className="text-faint">{s.examples}</span>
            </span>
            {i < STAGES.length - 1 && <ArrowRight size={12} className="text-faint" />}
          </span>
        ))}
        <span className="ml-auto flex items-center gap-1">
          {loading && <Spinner size={12} />}
          체인 위험도 = 최대 공격 위험도 + 8×(추가 단계 수) + 진행 시 5
        </span>
      </div>

      {/* ---- 목록 ---- */}
      {error && !data ? (
        <div className="panel">
          <EmptyState title="공격 체인을 불러오지 못했습니다" desc={error.message} />
        </div>
      ) : !data ? (
        <div className="space-y-3">
          <Skeleton className="h-48" />
          <Skeleton className="h-48" />
        </div>
      ) : chains.length === 0 ? (
        <div className="panel">
          <EmptyState
            icon={<GitBranch size={28} />}
            title="이어진 공격 흐름이 없습니다"
            desc="같은 출발지에서 공격이 2건 이상 이어지면 이곳에 표시됩니다. 조회 기간이나 묶음 간격을 늘려 보세요."
          />
        </div>
      ) : (
        <div className="space-y-3">
          {chains.map((c) => (
            <ChainCard key={c.id} chain={c} />
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, hint, tone }: { label: string; value: number; hint: string; tone?: "high" | "critical" }) {
  return (
    <div className="panel p-4" title={hint}>
      <p className="text-xs text-muted">{label}</p>
      <p
        className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
          tone === "critical" ? "text-sev-critical" : tone === "high" ? "text-sev-high" : "text-ink"
        }`}
      >
        {fmtNum(value)}
      </p>
      <p className="mt-0.5 truncate text-[10px] text-faint">{hint}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */

function ChainCard({ chain }: { chain: Chain }) {
  const { openIncident } = useUi();
  const sev = severityFromScore(chain.chainRisk);
  const reached = new Set(chain.stages as StageKey[]);
  const first = chain.events[0];

  return (
    <Panel
      className={`border-l-4 ${SEVERITY_CLASS[sev].border}`}
      bodyClassName="p-0"
      title={
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm">{chain.srcIp}</span>
          <span className="rounded bg-raised px-1 text-[10px] font-normal text-muted">
            {isPrivateIp(chain.srcIp) ? "내부" : "외부"}
          </span>
          {first && <DirectionBadge src={chain.srcIp} dst={first.destIp} />}
          {chain.escalated && (
            <span className="inline-flex items-center gap-1 rounded bg-sev-high/10 px-1.5 py-0.5 text-[10px] font-semibold text-sev-high ring-1 ring-inset ring-sev-high/30">
              <TrendingUp size={11} /> 공격 단계 진행
            </span>
          )}
          {chain.active && (
            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-sev-critical">
              <Radio size={11} className="animate-pulse" /> 진행 중
            </span>
          )}
        </span>
      }
      subtitle={`${fmtDateTime(chain.firstSeen)} ~ ${fmtSmart(chain.lastSeen)} (${fmtDuration(chain.firstSeen, chain.lastSeen)}) · 공격 ${chain.eventCount}건 · 플로우 ${fmtNum(chain.flowCount)}개 · 대상 ${chain.targetCount}곳`}
      actions={
        <div className="flex items-center gap-2">
          <SeverityBadge severity={sev} compact />
          <span className="text-right">
            <span className="block text-[10px] text-muted">체인 위험도</span>
            <span className={`font-mono text-lg font-semibold leading-none tabular-nums ${SEVERITY_CLASS[sev].text}`}>
              {chain.chainRisk.toFixed(1)}
            </span>
          </span>
        </div>
      }
    >
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,380px)_1fr]">
        {/* 단계 진행도 */}
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-faint">킬체인 단계</p>
          <ol className="flex items-stretch gap-1">
            {STAGES.map((s) => {
              const on = reached.has(s.key);
              return (
                <li
                  key={s.key}
                  className={`flex flex-1 flex-col items-center justify-center rounded-md border px-1 py-2 text-center ${
                    on
                      ? s.key === chain.highestStage
                        ? "border-sev-high/50 bg-sev-high/10"
                        : "border-accent/40 bg-accent/10"
                      : "border-dashed border-line bg-transparent"
                  }`}
                  title={`${s.tactic} · ${s.examples}`}
                >
                  <span className={`text-[10px] ${on ? "text-muted" : "text-faint"}`}>{s.order}단계</span>
                  <span className={`whitespace-nowrap text-xs font-semibold ${on ? "text-ink" : "text-faint"}`}>{s.short}</span>
                  <span className={`whitespace-nowrap text-[10px] ${on ? "text-muted" : "text-faint"}`}>{s.note}</span>
                </li>
              );
            })}
          </ol>
          {reached.has("ANOMALY") && <p className="mt-1.5 text-[10px] text-muted">+ 단계를 특정할 수 없는 이상 징후 포함</p>}
          <p className="mt-2 text-[10px] text-faint">
            대표 대상: <span className="font-mono text-muted">{chain.targets.join(", ") || "-"}</span>
          </p>
        </div>

        {/* 시간 흐름 */}
        <Timeline chain={chain} onOpen={openIncident} />
      </div>

      {/* 공격 목록 */}
      <div className="overflow-x-auto border-t border-line">
        <table className="w-full min-w-[760px]">
          <thead>
            <tr>
              <th className="th">시작</th>
              <th className="th">단계</th>
              <th className="th">공격</th>
              <th className="th">목적지</th>
              <th className="th text-right">플로우</th>
              <th className="th">위험도</th>
              <th className="th">ID</th>
            </tr>
          </thead>
          <tbody>
            {chain.events.map((e) => (
              <tr key={e.id} className="cursor-pointer hover:bg-raised" onClick={() => openIncident(e.id)}>
                <td className="td font-mono text-muted" title={fmtDateTime(e.firstSeen)}>
                  {e.active && <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-sev-critical" />}
                  {fmtSmart(e.firstSeen)}
                </td>
                <td className="td text-muted">{STAGE_LABEL[stageOf(e.attackType)]}</td>
                <td className="td">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm" style={{ background: attackInfo(e.attackType).color }} />
                    {e.attackSubtype ?? attackInfo(e.attackType).label}
                  </span>
                </td>
                <td className="td font-mono">{endpoint(e.destIp, e.destPort)}</td>
                <td className="td text-right font-mono text-muted">{fmtNum(e.flowCount)}</td>
                <td className={`td font-mono ${SEVERITY_CLASS[severityFromScore(e.riskScore)].text}`}>{e.riskScore.toFixed(1)}</td>
                <td className="td font-mono text-accent">#{e.id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/** 체인 안의 공격들을 시간축 위에 배치 (간이 간트 차트) */
function Timeline({ chain, onOpen }: { chain: Chain; onOpen: (id: string) => void }) {
  const start = chain.firstSeen?.getTime() ?? 0;
  const end = Math.max(chain.lastSeen?.getTime() ?? start, start + 60_000);
  const span = end - start;
  const lanes = STAGES.filter((s) => chain.events.some((e) => stageOf(e.attackType) === s.key));
  const hasAnomaly = chain.events.some((e) => stageOf(e.attackType) === "ANOMALY");
  const rows: Array<{ key: StageKey; label: string }> = [
    ...lanes.map((l) => ({ key: l.key, label: l.short })),
    ...(hasAnomaly ? [{ key: "ANOMALY" as StageKey, label: "미분류" }] : []),
  ];

  return (
    <div className="min-w-0">
      <div className="mb-2 flex items-center justify-between text-[10px] text-faint">
        <span className="font-semibold uppercase tracking-wider">시간 흐름</span>
        <span className="font-mono">
          {fmtSmart(chain.firstSeen)} → {fmtSmart(chain.lastSeen)} · {fmtAgo(chain.lastSeen)}
        </span>
      </div>
      <div className="space-y-1.5">
        {rows.map((row) => (
          <div key={row.key} className="grid grid-cols-[64px_1fr] items-center gap-2">
            <span className="truncate text-[10px] text-muted">{row.label}</span>
            <div className="relative h-6 rounded bg-raised">
              {chain.events
                .filter((e) => stageOf(e.attackType) === row.key)
                .map((e) => {
                  const s = (e.firstSeen?.getTime() ?? start) - start;
                  const f = (e.lastSeen?.getTime() ?? e.firstSeen?.getTime() ?? start) - start;
                  const left = (s / span) * 100;
                  const width = Math.max(1.5, ((f - s) / span) * 100);
                  const info = attackInfo(e.attackType);
                  return (
                    <button
                      key={e.id}
                      type="button"
                      onClick={() => onOpen(e.id)}
                      title={`${e.attackSubtype ?? info.label} · ${endpoint(e.destIp, e.destPort)} · 위험도 ${e.riskScore}`}
                      className="absolute top-1 h-4 rounded-sm ring-2 ring-surface transition hover:brightness-110"
                      style={{ left: `${Math.min(98.5, left)}%`, width: `${Math.min(100 - left, width)}%`, background: info.color }}
                      aria-label={`${info.label} 공격 #${e.id} 열기`}
                    />
                  );
                })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
