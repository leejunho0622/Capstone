import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CheckCircle2, Download, Eye, Search, ShieldOff, X } from "lucide-react";
import type { TriageStatus } from "../api/client";
import type { Severity } from "../api/types";
import { useLiveData } from "../store/liveData";
import { TRIAGE_META, TRIAGE_ORDER, useTriage } from "../store/triage";
import { useUi } from "../store/ui";
import { useSettings } from "../store/settings";
import { useHotkeys } from "../hooks/useHotkeys";
import { SEVERITY_META, SEVERITY_ORDER } from "../lib/severity";
import { ATTACK_ORDER, ATTACK_TYPES, attackInfo, normalizeAttackKey } from "../lib/attackTypes";
import { endpoint, fmtDateTime, fmtDuration, fmtSmart } from "../lib/format";
import { downloadCsv, timestampForFile } from "../lib/csv";
import { AttackTag, DirectionBadge, EmptyState, IpText, Pagination, RiskBar, SeverityBadge, TriageBadge } from "../components/ui";
import { DIRECTION_META, directionOf, type Direction } from "../lib/direction";
import { splitActionDetail } from "../components/detail/commands";
import { actionLabel } from "../lib/actions";

const PAGE_SIZE = 25;
type StatusFilter = "all" | "open" | TriageStatus;
type SortKey = "time" | "risk" | "flows";

export default function AlertsPage() {
  const { alerts, freshIds, connection } = useLiveData();
  const triage = useTriage();
  const { openIncident, toast } = useUi();
  const { settings } = useSettings();
  const [params, setParams] = useSearchParams();

  // ---- URL 에 필터 상태 저장 (새로고침/공유해도 유지) ----
  const q = params.get("q") ?? "";
  const severity = (params.get("severity") ?? "") as Severity | "";
  const status = (params.get("status") ?? "open") as StatusFilter;
  const type = params.get("type") ?? "";
  const activeOnly = params.get("active") === "1";
  const dir = (params.get("dir") ?? "") as Direction | "";
  const sort = (params.get("sort") ?? "time") as SortKey;
  const page = Math.max(1, Number(params.get("page") ?? 1));

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next, { replace: true });
  };

  const [qDraft, setQDraft] = useState(q);
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (qDraft !== q) setParam("q", qDraft.trim());
    }, 250);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDraft]);

  const filtered = useMemo(() => {
    const keyword = q.toLowerCase();
    const typeKey = type ? normalizeAttackKey(type) : null;
    const list = alerts.filter((a) => {
      if (severity && a.severity !== severity) return false;
      if (typeKey && normalizeAttackKey(a.attackType) !== typeKey) return false;
      if (activeOnly && !a.active) return false;
      if (dir && directionOf(a.srcIp, a.destIp) !== dir) return false;
      const st = triage.statusOf(a.id);
      if (status === "open" && !(st === "NEW" || st === "ACK")) return false;
      if (status !== "open" && status !== "all" && st !== status) return false;
      if (keyword) {
        const hay = `${a.id} ${a.srcIp} ${a.destIp}:${a.destPort ?? ""} ${a.attackType} ${a.attackSubtype ?? ""} ${a.action} ${actionLabel(a.action)}`.toLowerCase();
        if (!hay.includes(keyword)) return false;
      }
      return true;
    });
    return list.sort((a, b) =>
      sort === "risk"
        ? b.riskScore - a.riskScore || (b.lastSeen?.getTime() ?? 0) - (a.lastSeen?.getTime() ?? 0)
        : sort === "flows"
          ? b.flowCount - a.flowCount
          : (b.lastSeen?.getTime() ?? 0) - (a.lastSeen?.getTime() ?? 0)
    );
  }, [alerts, q, severity, type, status, sort, triage, activeOnly, dir]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const rows = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  // ---- 선택 ----
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(0);
  const allOnPageSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const bulk = async (ids: string[], st: TriageStatus) => {
    if (ids.length === 0) return;
    try {
      await triage.setStatus(ids, st);
      toast(`${ids.length}건을 '${TRIAGE_META[st].label}' 으로 변경했습니다`, "success");
      setSelected(new Set());
    } catch {
      toast("일부 상태 저장에 실패했습니다", "error");
    }
  };

  useHotkeys({
    j: () => setCursor((c) => Math.min(rows.length - 1, c + 1)),
    k: () => setCursor((c) => Math.max(0, c - 1)),
    x: () => rows[cursor] && toggle(rows[cursor].id),
    Enter: () => rows[cursor] && openIncident(rows[cursor].id),
    a: () => rows[cursor] && bulk([rows[cursor].id], "ACK"),
  });

  const exportCsv = () => {
    downloadCsv(
      `alerts_${timestampForFile()}.csv`,
      ["IncidentID", "최초탐지", "마지막탐지", "진행상태", "등급", "종합위험도", "최대위험도", "공격유형", "세부유형", "MITRE", "방향", "대표출발지", "고유출발지수", "대표목적지", "플로우수", "AI권장조치", "처리상태", "메모"],
      filtered.map((a) => {
        const rec = triage.get(a.id);
        return [
          a.id,
          fmtDateTime(a.firstSeen),
          fmtDateTime(a.lastSeen),
          a.active ? "진행 중" : "종료",
          SEVERITY_META[a.severity].label,
          a.riskScore,
          a.maxRisk,
          a.attackType,
          a.attackSubtype ?? "",
          attackInfo(a.attackType).mitre?.id ?? "",
          (() => {
            const d = directionOf(a.srcIp, a.destIp);
            return d ? DIRECTION_META[d].label : "";
          })(),
          a.srcIp,
          a.uniqueSrcIps,
          endpoint(a.destIp, a.destPort),
          a.flowCount,
          `${actionLabel(a.action)} (${a.action})`,
          TRIAGE_META[triage.statusOf(a.id)].label,
          rec?.note ?? "",
        ];
      })
    );
  };

  const counts = useMemo(() => {
    const c: Record<StatusFilter, number> = { all: alerts.length, open: 0, NEW: 0, ACK: 0, RESOLVED: 0, FALSE_POSITIVE: 0 };
    for (const a of alerts) {
      const st = triage.statusOf(a.id);
      c[st] += 1;
      if (st === "NEW" || st === "ACK") c.open += 1;
    }
    return c;
  }, [alerts, triage]);

  const hasFilter = q || severity || type || activeOnly || dir || status !== "open";

  return (
    <div className="mx-auto flex h-full max-w-[1880px] flex-col gap-3 p-4 lg:p-5">
      {/* ---- 상태 탭 ---- */}
      <div className="flex flex-wrap items-center gap-1 border-b border-line">
        {(["open", ...TRIAGE_ORDER, "all"] as StatusFilter[]).map((s) => (
          <button
            key={s}
            onClick={() => setParam("status", s === "open" ? "" : s)}
            className={`-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-xs font-medium transition ${
              status === s ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"
            }`}
          >
            {s === "open" ? "미처리" : s === "all" ? "전체" : TRIAGE_META[s].label}
            <span className="rounded bg-raised px-1.5 font-mono text-[10px] text-muted">{counts[s]}</span>
          </button>
        ))}
        <span className="ml-auto pb-2 text-[11px] text-faint">
          최근 {settings.alertWindowHours}시간 · 처리 상태 저장: {triage.mode === "server" ? "서버 (팀 공유)" : triage.mode === "local" ? "이 브라우저" : "확인 중"}
        </span>
      </div>

      {/* ---- 필터 ---- */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={qDraft}
            onChange={(e) => setQDraft(e.target.value)}
            placeholder="IP, 포트, 경보 ID, 세부 유형"
            className="input w-full pl-8"
            aria-label="경보 검색"
          />
        </div>
        <select className="input" value={severity} onChange={(e) => setParam("severity", e.target.value)} aria-label="등급">
          <option value="">모든 등급</option>
          {SEVERITY_ORDER.filter((s) => s !== "info").map((s) => (
            <option key={s} value={s}>
              {SEVERITY_META[s].label} · {SEVERITY_META[s].labelKo}
            </option>
          ))}
        </select>
        <select className="input" value={type} onChange={(e) => setParam("type", e.target.value)} aria-label="공격 유형">
          <option value="">모든 유형</option>
          {ATTACK_ORDER.map((k) => (
            <option key={k} value={ATTACK_TYPES[k].label}>
              {ATTACK_TYPES[k].label}
            </option>
          ))}
        </select>
        <select className="input" value={dir} onChange={(e) => setParam("dir", e.target.value)} aria-label="공격 방향">
          <option value="">모든 방향</option>
          {(Object.keys(DIRECTION_META) as Direction[]).map((d) => (
            <option key={d} value={d}>
              {DIRECTION_META[d].label} ({DIRECTION_META[d].short})
            </option>
          ))}
        </select>
        <select className="input" value={sort} onChange={(e) => setParam("sort", e.target.value === "time" ? "" : e.target.value)} aria-label="정렬">
          <option value="time">최근 활동순</option>
          <option value="risk">위험도순</option>
          <option value="flows">플로우 많은 순</option>
        </select>
        <label className="flex items-center gap-1.5 text-xs text-muted">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setParam("active", e.target.checked ? "1" : "")}
            className="accent-[rgb(var(--c-accent))]"
          />
          진행 중인 공격만
        </label>
        {hasFilter && (
          <button
            className="btn btn-ghost"
            onClick={() => {
              setQDraft("");
              setParams(new URLSearchParams(), { replace: true });
            }}
          >
            <X size={13} /> 필터 초기화
          </button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button className="btn" onClick={exportCsv} disabled={filtered.length === 0}>
            <Download size={13} /> CSV ({filtered.length})
          </button>
        </div>
      </div>

      {/* ---- 일괄 작업 바 ---- */}
      {selected.size > 0 && (
        <div className="flex animate-fade-in items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs">
          <b>{selected.size}건 선택</b>
          <span className="mx-1 h-4 w-px bg-line" />
          <button className="btn h-7" onClick={() => bulk([...selected], "ACK")}>
            <Eye size={13} /> 확인 중
          </button>
          <button className="btn h-7" onClick={() => bulk([...selected], "RESOLVED")}>
            <CheckCircle2 size={13} /> 조치 완료
          </button>
          <button className="btn h-7" onClick={() => bulk([...selected], "FALSE_POSITIVE")}>
            <ShieldOff size={13} /> 오탐 처리
          </button>
          <button className="btn btn-ghost ml-auto h-7" onClick={() => setSelected(new Set())}>
            선택 해제
          </button>
        </div>
      )}

      {/* ---- 표 ---- */}
      <div className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[980px]">
            <thead>
              <tr>
                <th className="th w-8">
                  <input
                    type="checkbox"
                    aria-label="이 페이지 전체 선택"
                    checked={allOnPageSelected}
                    onChange={() =>
                      setSelected((s) => {
                        const n = new Set(s);
                        rows.forEach((r) => (allOnPageSelected ? n.delete(r.id) : n.add(r.id)));
                        return n;
                      })
                    }
                    className="accent-[rgb(var(--c-accent))]"
                  />
                </th>
                <th className="th">등급</th>
                <th className="th">마지막 탐지</th>
                <th className="th hidden 2xl:table-cell">ID</th>
                <th className="th">공격 유형</th>
                <th className="th">출발지</th>
                <th className="th">목적지</th>
                <th className="th text-right">플로우</th>
                <th className="th">종합 위험도</th>
                <th className="th hidden 2xl:table-cell">AI 권장 조치</th>
                <th className="th">처리</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a, i) => (
                <tr
                  key={a.id}
                  onClick={() => {
                    setCursor(i);
                    openIncident(a.id);
                  }}
                  className={`cursor-pointer transition hover:bg-raised ${i === cursor ? "bg-raised/60 outline outline-1 -outline-offset-1 outline-accent/40" : ""} ${
                    freshIds.has(a.id) ? "animate-row-flash" : ""
                  } ${selected.has(a.id) ? "bg-accent/5" : ""}`}
                >
                  <td className="td" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selected.has(a.id)}
                      onChange={() => toggle(a.id)}
                      aria-label={`Flow ${a.id} 선택`}
                      className="accent-[rgb(var(--c-accent))]"
                    />
                  </td>
                  <td className="td">
                    <SeverityBadge severity={a.severity} compact />
                  </td>
                  <td
                    className="td font-mono text-muted"
                    title={`최초 ${fmtDateTime(a.firstSeen)}\n마지막 ${fmtDateTime(a.lastSeen)}\n지속 ${fmtDuration(a.firstSeen, a.lastSeen)}`}
                  >
                    {a.active && <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-sev-critical" title="진행 중" />}
                    {fmtSmart(a.lastSeen)}
                  </td>
                  <td className="td hidden font-mono text-muted 2xl:table-cell">#{a.id}</td>
                  <td className="td">
                    <AttackTag type={a.attackType} showMitre />
                    {a.attackSubtype && <span className="ml-1.5 hidden font-mono text-[10px] text-faint 2xl:inline">{a.attackSubtype}</span>}
                  </td>
                  <td className="td">
                    <span className="inline-flex items-center gap-1.5">
                      <IpText ip={a.srcIp} onClick={() => setParam("q", a.srcIp)} />
                      {a.uniqueSrcIps > 1 && <span className="text-[10px] text-muted">+{a.uniqueSrcIps - 1}</span>}
                      <DirectionBadge src={a.srcIp} dst={a.destIp} compact />
                    </span>
                  </td>
                  <td className="td">
                    <IpText ip={a.destIp} port={a.destPort} />
                    {a.uniqueDstPorts > 1 && <span className="ml-1 hidden text-[10px] text-muted 2xl:inline">포트 {a.uniqueDstPorts}개</span>}
                  </td>
                  <td className="td text-right font-mono text-ink">{a.flowCount.toLocaleString()}</td>
                  <td className="td">
                    <RiskBar score={a.riskScore} />
                  </td>
                  <td className="td hidden max-w-[160px] truncate text-muted 2xl:table-cell" title={splitActionDetail(a.actionDetail).message || a.action}>
                    {actionLabel(a.action)}
                  </td>
                  <td className="td">
                    <TriageBadge status={triage.statusOf(a.id)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <EmptyState
              title={
                connection === "down" && alerts.length === 0
                  ? "서버에 연결할 수 없습니다"
                  : connection === "connecting"
                    ? "경보를 불러오는 중..."
                    : hasFilter
                      ? "조건에 맞는 경보가 없습니다"
                      : "처리할 경보가 없습니다"
              }
              desc={
                connection === "down" && alerts.length === 0
                  ? "백엔드 서버(8080)가 실행 중인지 확인하세요. 연결되면 자동으로 다시 불러옵니다."
                  : hasFilter
                    ? "필터를 바꾸거나 초기화해 보세요."
                    : "새 공격이 탐지되면 자동으로 추가됩니다."
              }
            />
          )}
        </div>
        <Pagination
          page={safePage}
          pageCount={pageCount}
          total={filtered.length}
          pageSize={PAGE_SIZE}
          onChange={(p) => setParam("page", String(p))}
        />
      </div>
      <p className="text-[10px] text-faint">
        단축키: <span className="kbd">j</span>/<span className="kbd">k</span> 이동 · <span className="kbd">x</span> 선택 ·{" "}
        <span className="kbd">Enter</span> 상세 · <span className="kbd">a</span> 확인 처리
      </p>
    </div>
  );
}
