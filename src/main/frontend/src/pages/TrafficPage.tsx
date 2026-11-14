import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Download, RotateCcw, Search } from "lucide-react";
import { getFlows, type FlowQuery } from "../api/client";
import type { FlowWithVerdict, TcpFlags } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useSettings } from "../store/settings";
import { useUi } from "../store/ui";
import { ATTACK_ORDER, ATTACK_TYPES } from "../lib/attackTypes";
import { severityFromScore } from "../lib/severity";
import { endpoint, fmtDateTime, fmtDuration, fmtSmart } from "../lib/format";
import { downloadCsv, timestampForFile } from "../lib/csv";
import { AttackTag, EmptyState, Field, IpText, Pagination, SeverityBadge, Spinner } from "../components/ui";

const PAGE_SIZE = 50;

/** URL 파라미터 ↔ 검색 조건 */
const FILTER_KEYS = ["q", "srcIp", "destIp", "port", "protocol", "verdict", "attackType", "hours"] as const;
type FilterKey = (typeof FILTER_KEYS)[number];
type Filters = Record<FilterKey, string>;

export default function TrafficPage() {
  const [params, setParams] = useSearchParams();
  const { settings } = useSettings();
  const { openFlow, openIncident } = useUi();

  const applied: Filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""])) as Filters;
  const page = Math.max(1, Number(params.get("page") ?? 1));
  const [draft, setDraft] = useState<Filters>(applied);
  const appliedKey = FILTER_KEYS.map((k) => applied[k]).join("|");

  // 다른 화면에서 ?srcIp= 로 들어오면 입력칸도 맞춰줌
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- URL → 입력 상태 동기화
    setDraft(applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appliedKey]);

  const apply = (next: Filters, nextPage = 1) => {
    const p = new URLSearchParams();
    FILTER_KEYS.forEach((k) => next[k].trim() && p.set(k, next[k].trim()));
    if (nextPage > 1) p.set("page", String(nextPage));
    setParams(p, { replace: true });
  };

  const query: FlowQuery = {
    page: page - 1,
    size: PAGE_SIZE,
    q: applied.q || undefined,
    srcIp: applied.srcIp || undefined,
    destIp: applied.destIp || undefined,
    port: applied.port || undefined,
    protocol: applied.protocol || undefined,
    verdict: (applied.verdict as FlowQuery["verdict"]) || undefined,
    attackType: applied.attackType || undefined,
    hours: applied.hours ? Number(applied.hours) : undefined,
  };

  // 첫 페이지를 보고 있을 때만 자동 갱신 (뒤 페이지는 목록이 밀리지 않도록 고정)
  const { data, error, loading, lastUpdated, refresh } = usePolling(
    (signal) => getFlows(query, signal),
    [appliedKey, page],
    { intervalMs: Math.max(10_000, settings.pollMs * 2), enabled: !settings.paused && page === 1 }
  );

  const rows = data?.items ?? [];
  const set = (k: FilterKey, v: string) => setDraft((d) => ({ ...d, [k]: v }));
  const empty: Filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, ""])) as Filters;
  const activeCount = FILTER_KEYS.filter((k) => applied[k]).length;

  const exportCsv = () =>
    downloadCsv(
      `traffic_${timestampForFile()}_p${page}.csv`,
      ["FlowID", "시작", "종료", "출발지", "목적지", "프로토콜", "SYN", "ACK", "FIN", "RST", "PSH", "URG", "AI판정", "공격유형", "위험점수"],
      rows.map(({ flow, ai }) => [
        flow.flowId,
        fmtDateTime(flow.startTime),
        fmtDateTime(flow.endTime),
        endpoint(flow.srcIp, flow.srcPort),
        endpoint(flow.destIp, flow.destPort),
        flow.protocol,
        flow.flags.syn,
        flow.flags.ack,
        flow.flags.fin,
        flow.flags.rst,
        flow.flags.psh,
        flow.flags.urg,
        ai?.prediction ?? "",
        ai?.attackType ?? "",
        ai?.riskScore ?? "",
      ])
    );

  return (
    <div className="mx-auto flex h-full max-w-[1880px] flex-col gap-3 p-4 lg:p-5">
      {/* ---- 검색 조건 ---- */}
      <form
        className="panel grid grid-cols-2 gap-3 p-3 md:grid-cols-4 xl:grid-cols-[2fr_1.2fr_1.2fr_0.7fr_0.8fr_0.9fr_1fr_0.9fr_auto]"
        onSubmit={(e) => {
          e.preventDefault();
          apply(draft);
        }}
      >
        <Field label="통합 검색">
          <div className="relative">
            <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
            <input className="input w-full pl-7" value={draft.q} onChange={(e) => set("q", e.target.value)} placeholder="IP 또는 Flow ID" />
          </div>
        </Field>
        <Field label="출발지 IP">
          <input className="input w-full font-mono" value={draft.srcIp} onChange={(e) => set("srcIp", e.target.value)} placeholder="192.168.0.14" />
        </Field>
        <Field label="목적지 IP">
          <input className="input w-full font-mono" value={draft.destIp} onChange={(e) => set("destIp", e.target.value)} placeholder="10.0.0.5" />
        </Field>
        <Field label="목적지 포트">
          <input className="input w-full font-mono" inputMode="numeric" value={draft.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, ""))} placeholder="22" />
        </Field>
        <Field label="프로토콜">
          <select className="input w-full" value={draft.protocol} onChange={(e) => set("protocol", e.target.value)}>
            <option value="">전체</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </Field>
        <Field label="AI 판정">
          <select className="input w-full" value={draft.verdict} onChange={(e) => set("verdict", e.target.value)}>
            <option value="">전체</option>
            <option value="attack">공격</option>
            <option value="normal">정상</option>
          </select>
        </Field>
        <Field label="공격 유형">
          <select className="input w-full" value={draft.attackType} onChange={(e) => set("attackType", e.target.value)}>
            <option value="">전체</option>
            {ATTACK_ORDER.map((k) => (
              <option key={k} value={k}>
                {ATTACK_TYPES[k].label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="기간">
          <select className="input w-full" value={draft.hours} onChange={(e) => set("hours", e.target.value)}>
            <option value="">전체</option>
            <option value="1">최근 1시간</option>
            <option value="24">최근 24시간</option>
            <option value="168">최근 7일</option>
            <option value="720">최근 30일</option>
          </select>
        </Field>
        <div className="col-span-2 flex items-end gap-2 md:col-span-4 xl:col-span-1">
          <button type="submit" className="btn btn-primary">
            <Search size={13} /> 조회
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              setDraft(empty);
              apply(empty);
            }}
            disabled={activeCount === 0}
            title="조건 초기화"
          >
            <RotateCcw size={13} />
          </button>
        </div>
      </form>

      {/* ---- 표 ---- */}
      <div className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="panel-header">
          <div className="flex items-center gap-2 text-xs">
            <span className="panel-title">네트워크 플로우</span>
            <span className="text-muted">
              {data ? `총 ${data.totalElements.toLocaleString()}건` : ""}
              {activeCount > 0 && ` · 조건 ${activeCount}개 적용`}
            </span>
            {loading && <Spinner size={12} />}
          </div>
          <div className="flex items-center gap-2 text-[11px] text-faint">
            {page === 1 && !settings.paused ? "자동 갱신 중" : "자동 갱신 멈춤 (첫 페이지에서만 동작)"}
            {lastUpdated && ` · ${fmtSmart(lastUpdated)}`}
            <button className="btn h-7" onClick={refresh}>
              새로고침
            </button>
            <button className="btn h-7" onClick={exportCsv} disabled={rows.length === 0}>
              <Download size={13} /> CSV
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-auto">
          {error && !data ? (
            <EmptyState title="트래픽을 불러오지 못했습니다" desc={error.message} />
          ) : (
            <table className="w-full min-w-[1100px]">
              <thead>
                <tr>
                  <th className="th">시작 시각</th>
                  <th className="th">Flow ID</th>
                  <th className="th">출발지</th>
                  <th className="th">목적지</th>
                  <th className="th">프로토콜</th>
                  <th className="th">지속</th>
                  <th className="th">TCP 플래그</th>
                  <th className="th">AI 판정</th>
                  <th className="th">소속 공격</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <TrafficRow
                    key={row.flow.flowId}
                    row={row}
                    onOpen={() => openFlow(row.flow.flowId)}
                    onOpenIncident={(id) => openIncident(id)}
                    onFilterSrc={() => apply({ ...applied, srcIp: row.flow.srcIp })}
                    onFilterDst={() => apply({ ...applied, destIp: row.flow.destIp })}
                  />
                ))}
              </tbody>
            </table>
          )}
          {data && rows.length === 0 && <EmptyState title="조건에 맞는 트래픽이 없습니다" />}
        </div>
        <Pagination
          page={page}
          pageCount={data?.totalPages ?? 1}
          total={data?.totalElements}
          pageSize={PAGE_SIZE}
          onChange={(p) => apply(applied, p)}
        />
      </div>
    </div>
  );
}

function TrafficRow({
  row,
  onOpen,
  onOpenIncident,
  onFilterSrc,
  onFilterDst,
}: {
  row: FlowWithVerdict;
  onOpen: () => void;
  onOpenIncident: (id: string) => void;
  onFilterSrc: () => void;
  onFilterDst: () => void;
}) {
  const { flow, ai } = row;
  return (
    <tr onClick={onOpen} className="cursor-pointer transition hover:bg-raised">
      <td className="td font-mono text-muted" title={fmtDateTime(flow.startTime)}>
        {fmtSmart(flow.startTime)}
      </td>
      <td className="td font-mono text-muted">{flow.flowId}</td>
      <td className="td">
        <IpText ip={flow.srcIp} port={flow.srcPort} onClick={onFilterSrc} />
      </td>
      <td className="td">
        <IpText ip={flow.destIp} port={flow.destPort} onClick={onFilterDst} />
      </td>
      <td className="td text-muted">{flow.protocol}</td>
      <td className="td font-mono text-muted">{fmtDuration(flow.startTime, flow.endTime)}</td>
      <td className="td">
        <FlagChips flags={flow.flags} />
      </td>
      <td className="td">
        {!ai ? (
          <span className="text-[11px] text-faint">분석 대기</span>
        ) : ai.isAttack ? (
          <span className="flex items-center gap-2">
            <SeverityBadge severity={severityFromScore(ai.riskScore)} compact />
            <AttackTag type={ai.attackSubtype ?? ai.attackType} />
            <span className="font-mono text-[11px] text-muted">{ai.riskScore.toFixed(0)}</span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-sev-low" /> 정상
          </span>
        )}
      </td>
      <td className="td">
        {flow.attackId ? (
          <button
            className="font-mono text-[11px] text-accent hover:underline"
            onClick={(e) => {
              e.stopPropagation();
              onOpenIncident(flow.attackId!);
            }}
          >
            #{flow.attackId}
          </button>
        ) : (
          <span className="text-faint">-</span>
        )}
      </td>
    </tr>
  );
}

function FlagChips({ flags }: { flags: TcpFlags }) {
  const list: Array<[string, number]> = [
    ["S", flags.syn],
    ["A", flags.ack],
    ["F", flags.fin],
    ["R", flags.rst],
    ["P", flags.psh],
    ["U", flags.urg],
  ];
  const any = list.some(([, v]) => v > 0);
  if (!any) return <span className="text-faint">-</span>;
  return (
    <span className="inline-flex gap-0.5 font-mono text-[10px]" title={list.map(([k, v]) => `${k}:${v}`).join(" ")}>
      {list.map(([k, v]) => (
        <span
          key={k}
          className={`inline-flex h-4 min-w-4 items-center justify-center rounded-sm px-0.5 ${
            v > 0 ? "bg-accent/20 text-ink" : "bg-raised text-faint"
          }`}
        >
          {k}
          {v > 1 && <sub className="ml-px text-[8px] text-muted">{v > 99 ? "99+" : v}</sub>}
        </span>
      ))}
    </span>
  );
}
