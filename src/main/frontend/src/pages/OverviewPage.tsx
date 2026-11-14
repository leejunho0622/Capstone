import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Activity, ArrowRight, Gauge, ListChecks, Network, ServerOff, ShieldAlert } from "lucide-react";
import type { Alert, Severity } from "../api/types";
import { useLiveData } from "../store/liveData";
import { useTriage } from "../store/triage";
import { useUi } from "../store/ui";
import { useThreat } from "../hooks/useThreat";
import { AttackDonut, Sparkline, TrendChart, WeeklyBars } from "../components/charts";
import {
  AttackTag,
  DirectionBadge,
  EmptyState,
  IpText,
  Panel,
  RiskBar,
  Segmented,
  SeverityBadge,
  Skeleton,
  TriageBadge,
} from "../components/ui";
import { SEVERITY_CLASS, SEVERITY_META, SEVERITY_ORDER, THREAT_META } from "../lib/severity";
import { attackInfo } from "../lib/attackTypes";
import { fmtAgo, fmtNum, fmtSmart } from "../lib/format";

export default function OverviewPage() {
  const live = useLiveData();
  const threat = useThreat();
  const navigate = useNavigate();
  const [donutPeriod, setDonutPeriod] = useState<"today" | "all">("today");
  const loading = !live.summary && live.connection === "connecting";
  /** 서버에 연결되지 않아 받은 데이터가 없는 상태 */
  const offline = live.connection === "down";

  const hourlyTotal = live.hourly?.reduce((s, p) => s + p.count, 0) ?? 0;
  const weeklySpark = live.weekly?.map((p) => p.count) ?? [];
  const threatMeta = THREAT_META[threat.level];

  return (
    <div className="mx-auto max-w-[1880px] space-y-4 p-4 lg:p-5">
      {/* ---------- KPI ---------- */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi label="위협 수준" loading={loading} icon={<ShieldAlert size={15} />} tone="accent" className="col-span-2 lg:col-span-1">
          <div className="flex items-center gap-2">
            <span className={`rounded-md px-2 py-0.5 text-lg font-bold ring-1 ring-inset ${threatMeta.className}`}>
              {threatMeta.label}
            </span>
            {live.summary?.realtimeAttack && (
              <span className="flex items-center gap-1 text-[11px] font-semibold text-sev-critical">
                <ShieldAlert size={13} /> 공격 진행 중
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-muted">{threatMeta.desc}</p>
        </Kpi>

        <Kpi label="오늘 탐지 공격" loading={loading} icon={<Activity size={15} />} tone="critical" hint="attack_events 기준 (여러 플로우를 묶은 공격 1건)">
          <div className="flex items-end justify-between gap-3">
            <BigNumber value={fmtNum(live.summary?.todayAttacks)} unit="건" />
            <span className="mb-0.5 text-[11px] text-muted">
              진행 중 <b className={live.summary?.activeAttacks ? "text-sev-critical" : "text-ink"}>{live.summary?.activeAttacks ?? 0}</b>
            </span>
          </div>
          <Sparkline data={weeklySpark} />
        </Kpi>

        <Kpi
          label="미처리 경보"
          loading={loading}
          icon={<ListChecks size={15} />}
          tone="high"
          action={
            <Link to="/alerts?status=open" className="text-[11px] text-accent hover:underline">
              처리하기
            </Link>
          }
        >
          <BigNumber value={fmtNum(threat.open.length)} unit="건" />
          <p className="mt-2 text-[11px] text-muted">
            신규 <b className="text-ink">{threat.newCount}</b> · High 이상 <b className="text-ink">{threat.openHigh}</b>
          </p>
        </Kpi>

        <Kpi label="오늘 공격 위험도" loading={loading} icon={<Gauge size={15} />} tone="accent" hint="오늘 공격들의 종합 위험도(event_risk) 평균 / 최대">
          <BigNumber value={live.summary ? live.summary.avgRisk.toFixed(1) : "-"} unit="평균" />
          <div className="relative mt-3 h-1.5 rounded-full bg-line" aria-hidden>
            <div className="h-full rounded-full bg-accent" style={{ width: `${live.summary?.avgRisk ?? 0}%` }} />
            <span
              className="absolute -top-1 h-3.5 w-0.5 rounded bg-sev-critical"
              style={{ left: `${Math.min(99, live.summary?.maxRisk ?? 0)}%` }}
              title={`최대 ${live.summary?.maxRisk ?? 0}`}
            />
          </div>
          <p className="mt-1.5 text-[10px] text-muted">
            최대 <b className="font-mono text-ink">{live.summary?.maxRisk.toFixed(1) ?? "-"}</b> (빨간 눈금)
          </p>
        </Kpi>

        <Kpi label="오늘 수집 트래픽" loading={loading} icon={<Network size={15} />} tone="brand" hint="Suricata 가 기록한 연결(flow) 수">
          <BigNumber value={fmtNum(live.summary?.todayFlows)} unit="플로우" />
          <p className="mt-2 text-[11px] text-muted">
            누적 <b className="text-ink">{fmtNum(live.summary?.totalFlows)}</b> · 24시간 공격 <b className="text-ink">{fmtNum(hourlyTotal)}</b>건
          </p>
        </Kpi>
      </div>

      {/* ---------- 추이 + 유형 (노트북 폭에서도 범례가 잘리지 않도록 3:2) ---------- */}
      <div className="grid gap-4 xl:grid-cols-5 2xl:grid-cols-3">
        <Panel
          className="xl:col-span-3 2xl:col-span-2"
          title="최근 24시간 공격 추이"
          subtitle="시간대별 공격 시작 건수 · 맨 오른쪽이 현재 시각"
          actions={<span className="font-mono text-xs text-muted">총 {fmtNum(hourlyTotal)}건</span>}
        >
          {live.hourly ? (
            <TrendChart data={live.hourly} height={220} labelInterval={2} color="rgb(var(--c-accent))" />
          ) : offline ? (
            <Offline height={220} />
          ) : (
            <Skeleton className="h-[220px]" />
          )}
        </Panel>

        <Panel
          className="xl:col-span-2 2xl:col-span-1"
          title="공격 유형 분포"
          subtitle="항목을 누르면 해당 유형 경보만 봅니다"
          actions={
            <Segmented
              label="기간"
              value={donutPeriod}
              onChange={setDonutPeriod}
              options={[
                { value: "today", label: "오늘" },
                { value: "all", label: "전체" },
              ]}
            />
          }
        >
          {(donutPeriod === "today" ? live.attackTypesToday : live.attackTypesAll) ? (
            <AttackDonut
              data={(donutPeriod === "today" ? live.attackTypesToday : live.attackTypesAll) ?? []}
              onSelect={(label) => navigate(`/alerts?type=${encodeURIComponent(label)}`)}
            />
          ) : offline ? (
            <Offline height={168} />
          ) : (
            <Skeleton className="h-[168px]" />
          )}
        </Panel>
      </div>

      {/* ---------- 실시간 피드 + 상위 출발지 ----------
          1536px 미만(노트북)에서는 피드 표가 잘리지 않도록 전체 폭을 쓰고,
          상위 출발지는 아래 2×2 영역으로 이동 */}
      <div className="grid gap-4 2xl:grid-cols-3">
        <LiveFeed className="2xl:col-span-2" />
        <TopSources alerts={live.alerts} className="hidden 2xl:flex" />
      </div>

      {/* ---------- 하단 ---------- */}
      <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        <TopSources alerts={live.alerts} className="2xl:hidden" />
        <Panel title="최근 7일 공격" subtitle="일별 공격 건수 (오늘 강조)">
          {live.weekly ? <WeeklyBars data={live.weekly} height={180} /> : offline ? <Offline height={180} /> : <Skeleton className="h-[180px]" />}
        </Panel>
        <TopTargets alerts={live.alerts} />
        <SeverityBreakdown alerts={live.alerts} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

const KPI_TONE = {
  accent: "bg-accent/10 text-accent",
  brand: "bg-brand/10 text-brand",
  critical: "bg-sev-critical/10 text-sev-critical",
  high: "bg-sev-high/10 text-sev-high",
} as const;

function Kpi({
  label,
  hint,
  action,
  loading,
  icon,
  tone = "accent",
  className = "",
  children,
}: {
  label: string;
  hint?: string;
  action?: ReactNode;
  loading?: boolean;
  icon?: ReactNode;
  tone?: keyof typeof KPI_TONE;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={`panel min-w-0 p-4 ${className}`} title={hint}>
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <p className="flex min-w-0 items-center gap-2 text-xs font-medium text-muted">
          {icon && <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md ${KPI_TONE[tone]}`}>{icon}</span>}
          <span className="truncate">{label}</span>
        </p>
        {action}
      </div>
      {loading ? <Skeleton className="h-12" /> : children}
    </div>
  );
}

function BigNumber({ value, unit }: { value: string; unit?: string }) {
  return (
    <p className="font-mono text-[28px] font-semibold leading-none tabular-nums tracking-tight text-ink">
      {value}
      {unit && <span className="ml-1 font-sans text-xs font-normal text-muted">{unit}</span>}
    </p>
  );
}

function LiveFeed({ className = "" }: { className?: string }) {
  const { alerts, freshIds } = useLiveData();
  const { statusOf } = useTriage();
  const { openIncident } = useUi();
  const rows = useMemo(
    () =>
      [...alerts]
        .sort((a, b) => (b.lastSeen?.getTime() ?? 0) - (a.lastSeen?.getTime() ?? 0))
        .slice(0, 10),
    [alerts]
  );

  return (
    <Panel
      className={className}
      title="실시간 경보 피드"
      subtitle="최근 활동 순 공격 목록 · 행을 누르면 상세"
      bodyClassName="p-0"
      actions={
        <Link to="/alerts" className="btn btn-ghost h-7">
          전체 보기 <ArrowRight size={13} />
        </Link>
      }
    >
      {rows.length === 0 ? (
        <EmptyState title="탐지된 경보가 없습니다" desc="새 공격이 탐지되면 이곳에 실시간으로 표시됩니다." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead>
              <tr>
                <th className="th">등급</th>
                <th className="th">마지막 탐지</th>
                <th className="th">유형</th>
                <th className="th">출발지 → 목적지</th>
                <th className="th text-right">플로우</th>
                <th className="th">위험도</th>
                <th className="th">상태</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => openIncident(a.id)}
                  className={`cursor-pointer transition hover:bg-raised ${freshIds.has(a.id) ? "animate-row-flash" : ""}`}
                >
                  <td className="td">
                    <SeverityBadge severity={a.severity} compact />
                  </td>
                  <td className="td font-mono text-muted" title={a.lastSeen?.toLocaleString()}>
                    {a.active && <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-sev-critical" title="진행 중" />}
                    {fmtSmart(a.lastSeen)}
                  </td>
                  <td className="td">
                    <AttackTag type={a.attackType} />
                    {a.attackSubtype && <span className="ml-1.5 text-[10px] text-faint">{a.attackSubtype.split("-")[1] ?? ""}</span>}
                  </td>
                  <td className="td">
                    <IpText ip={a.srcIp} />
                    {a.uniqueSrcIps > 1 && <span className="ml-1 text-[10px] text-muted">+{a.uniqueSrcIps - 1}</span>}
                    <span className="mx-1.5 text-faint">→</span>
                    <IpText ip={a.destIp} port={a.destPort} />
                    <span className="ml-1.5">
                      <DirectionBadge src={a.srcIp} dst={a.destIp} compact />
                    </span>
                  </td>
                  <td className="td text-right font-mono text-muted">{fmtNum(a.flowCount)}</td>
                  <td className="td">
                    <RiskBar score={a.riskScore} />
                  </td>
                  <td className="td">
                    <TriageBadge status={statusOf(a.id)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function maxSeverity(list: Severity[]): Severity {
  return list.reduce<Severity>(
    (m, s) => (SEVERITY_META[s].rank > SEVERITY_META[m].rank ? s : m),
    "info"
  );
}

function TopSources({ alerts, className = "" }: { alerts: Alert[]; className?: string }) {
  const navigate = useNavigate();
  const rows = useMemo(() => {
    const map = new Map<string, { ip: string; count: number; sev: Severity[]; types: Set<string>; last: number; targets: Set<string> }>();
    for (const a of alerts) {
      const r = map.get(a.srcIp) ?? {
        ip: a.srcIp,
        count: 0,
        sev: [],
        types: new Set<string>(),
        last: 0,
        targets: new Set<string>(),
      };
      r.count += 1;
      r.sev.push(a.severity);
      r.types.add(a.attackType);
      r.targets.add(a.destIp);
      r.last = Math.max(r.last, a.lastSeen?.getTime() ?? 0);
      map.set(a.srcIp, r);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 8);
  }, [alerts]);
  const max = Math.max(1, ...rows.map((r) => r.count));

  return (
    <Panel className={className} title="상위 공격 출발지" subtitle="공격 건수 기준 · 누르면 해당 IP 경보만 보기">
      {rows.length === 0 ? (
        <EmptyState title="데이터 없음" />
      ) : (
        <ul className="space-y-2.5">
          {rows.map((r) => {
            const sev = maxSeverity(r.sev);
            return (
              <li key={r.ip}>
                <button
                  className="group w-full text-left"
                  onClick={() => navigate(`/alerts?q=${encodeURIComponent(r.ip)}`)}
                >
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="flex min-w-0 items-center gap-2">
                      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_CLASS[sev].dot}`} title={SEVERITY_META[sev].label} />
                      <span className="truncate font-mono text-ink group-hover:text-accent">{r.ip}</span>
                    </span>
                    <span className="font-mono tabular-nums text-ink">{r.count}</span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-line/60">
                    <div className="h-full rounded-full bg-accent/70" style={{ width: `${(r.count / max) * 100}%` }} />
                  </div>
                  <p className="mt-1 truncate text-[10px] text-faint">
                    {[...r.types].map((t) => attackInfo(t).label).join(", ")} · 대상 {r.targets.size}곳 ·{" "}
                    {fmtAgo(new Date(r.last))}
                  </p>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function TopTargets({ alerts }: { alerts: Alert[] }) {
  const rows = useMemo(() => {
    const map = new Map<string, { key: string; ip: string; port: number | null; count: number }>();
    for (const a of alerts) {
      const key = `${a.destIp}:${a.destPort ?? ""}`;
      const r = map.get(key) ?? { key, ip: a.destIp, port: a.destPort, count: 0 };
      r.count += 1;
      map.set(key, r);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 6);
  }, [alerts]);
  const total = alerts.length || 1;

  return (
    <Panel title="공격 대상 서비스" subtitle="대표 목적지 IP:포트 기준 공격 건수">
      {rows.length === 0 ? (
        <EmptyState title="데이터 없음" />
      ) : (
        <ul className="divide-y divide-line/60">
          {rows.map((r) => (
            <li key={r.key} className="flex items-center justify-between gap-2 py-2 text-xs">
              <IpText ip={r.ip} port={r.port} />
              <span className="flex items-center gap-2">
                <span className="w-10 text-right font-mono tabular-nums text-ink">{r.count}</span>
                <span className="w-12 text-right font-mono tabular-nums text-muted">
                  {((r.count / total) * 100).toFixed(1)}%
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function SeverityBreakdown({ alerts }: { alerts: Alert[] }) {
  const { statusOf } = useTriage();
  const navigate = useNavigate();
  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, { total: 0, open: 0 }])) as Record<
      Severity,
      { total: number; open: number }
    >;
    for (const a of alerts) {
      c[a.severity].total += 1;
      const st = statusOf(a.id);
      if (st === "NEW" || st === "ACK") c[a.severity].open += 1;
    }
    return c;
  }, [alerts, statusOf]);
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s].total));

  return (
    <Panel title="등급별 경보" subtitle="막대: 전체 / 진한 부분: 미처리">
      <ul className="space-y-3">
        {SEVERITY_ORDER.filter((s) => s !== "info").map((s) => (
          <li key={s}>
            <button className="w-full text-left" onClick={() => navigate(`/alerts?severity=${s}`)}>
              <div className="flex items-center justify-between text-xs">
                <span className="text-ink">
                  {SEVERITY_META[s].label} <span className="text-[10px] text-faint">{SEVERITY_META[s].labelKo}</span>
                </span>
                <span className="font-mono tabular-nums text-muted">
                  <b className="text-ink">{counts[s].open}</b> / {counts[s].total}
                </span>
              </div>
              <div className="relative mt-1 h-2 overflow-hidden rounded-sm bg-line/50">
                <div
                  className={`absolute inset-y-0 left-0 rounded-sm opacity-35 ${SEVERITY_CLASS[s].bar}`}
                  style={{ width: `${(counts[s].total / max) * 100}%` }}
                />
                <div
                  className={`absolute inset-y-0 left-0 rounded-sm ${SEVERITY_CLASS[s].bar}`}
                  style={{ width: `${(counts[s].open / max) * 100}%` }}
                />
              </div>
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Offline({ height }: { height: number }) {
  return (
    <div
      style={{ height }}
      className="flex flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-line text-center"
    >
      <ServerOff size={20} className="text-faint" />
      <p className="text-xs font-medium text-ink">데이터를 불러올 수 없습니다</p>
      <p className="text-[11px] text-muted">백엔드 서버(8080) 연결을 확인하세요</p>
    </div>
  );
}
