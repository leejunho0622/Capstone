import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Inbox, Loader2 } from "lucide-react";
import type { Severity } from "../api/types";
import type { TriageStatus } from "../api/client";
import { SEVERITY_CLASS, SEVERITY_META, severityFromScore } from "../lib/severity";
import { TRIAGE_META } from "../store/triage";
import { attackInfo } from "../lib/attackTypes";
import { isPrivateIp, portName } from "../lib/format";
import { DIRECTION_META, directionOf } from "../lib/direction";

/* =========================================================
   공통 UI 조각
   ========================================================= */

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = "",
  bodyClassName = "p-4",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`panel flex min-w-0 flex-col ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          <div className="min-w-0">
            {title && <h2 className="panel-title">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[11px] text-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={`min-h-0 flex-1 ${bodyClassName}`}>{children}</div>
    </section>
  );
}

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const c = SEVERITY_CLASS[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${c.chip}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${c.dot}`} aria-hidden />
      {compact ? SEVERITY_META[severity].label : `${SEVERITY_META[severity].label} · ${SEVERITY_META[severity].labelKo}`}
    </span>
  );
}

export function TriageBadge({ status }: { status: TriageStatus }) {
  const m = TRIAGE_META[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-ink">
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} aria-hidden />
      {m.label}
    </span>
  );
}

export function AttackTag({ type, showMitre = false }: { type: string; showMitre?: boolean }) {
  const info = attackInfo(type);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink">
      <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: info.color }} aria-hidden />
      {info.label}
      {showMitre && info.mitre && (
        <span className="font-mono text-[10px] text-muted">{info.mitre.id}</span>
      )}
    </span>
  );
}

export function RiskBar({ score }: { score: number }) {
  const sev: Severity = severityFromScore(score);
  return (
    <span className="inline-flex items-center gap-2">
      <span className="w-8 text-right font-mono text-xs tabular-nums text-ink">{score.toFixed(0)}</span>
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-line" aria-hidden>
        <span
          className={`block h-full rounded-full ${SEVERITY_CLASS[sev].bar}`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </span>
    </span>
  );
}

export function IpText({
  ip,
  port,
  onClick,
  showScope = false,
}: {
  ip: string;
  port?: number | null;
  onClick?: () => void;
  showScope?: boolean;
}) {
  const name = portName(port ?? null);
  const content = (
    <>
      <span className="text-ink">{ip}</span>
      {port !== undefined && port !== null && (
        <span className="text-muted">
          :{port}
          {name && <span className="ml-1 font-sans text-[10px] text-faint">{name}</span>}
        </span>
      )}
      {showScope && ip !== "-" && (
        <span className="ml-1.5 rounded bg-raised px-1 font-sans text-[9px] text-muted">
          {isPrivateIp(ip) ? "내부" : "외부"}
        </span>
      )}
    </>
  );
  if (!onClick) return <span className="font-mono text-xs">{content}</span>;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title="이 IP 로 필터링"
      className="rounded font-mono text-xs underline-offset-2 hover:underline"
    >
      {content}
    </button>
  );
}

export function EmptyState({ title, desc, icon }: { title: string; desc?: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <div className="text-faint">{icon ?? <Inbox size={28} />}</div>
      <p className="text-sm font-medium text-ink">{title}</p>
      {desc && <p className="max-w-sm text-xs text-muted">{desc}</p>}
    </div>
  );
}

export function Spinner({ size = 14 }: { size?: number }) {
  return <Loader2 size={size} className="animate-spin text-muted" aria-label="불러오는 중" />;
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-raised ${className}`} />;
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-md border border-line bg-canvas p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={`h-6 rounded px-2.5 text-[11px] font-medium transition ${
            value === o.value ? "bg-surface text-accent shadow-sm ring-1 ring-line" : "text-muted hover:text-ink"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Pagination({
  page,
  pageCount,
  onChange,
  total,
  pageSize,
}: {
  page: number; // 1부터
  pageCount: number;
  onChange: (p: number) => void;
  total?: number;
  pageSize?: number;
}) {
  const from = total !== undefined && pageSize ? (page - 1) * pageSize + 1 : null;
  const to = total !== undefined && pageSize ? Math.min(total, page * pageSize) : null;
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line px-3 py-2 text-xs text-muted">
      <span>
        {total !== undefined && from !== null && to !== null
          ? total === 0
            ? "0건"
            : `${from.toLocaleString()}–${to.toLocaleString()} / 총 ${total.toLocaleString()}건`
          : null}
      </span>
      <div className="flex items-center gap-1">
        <button className="btn btn-ghost h-7 px-1.5" onClick={() => onChange(1)} disabled={page <= 1} aria-label="첫 페이지">
          <ChevronsLeft size={14} />
        </button>
        <button className="btn btn-ghost h-7 px-1.5" onClick={() => onChange(page - 1)} disabled={page <= 1} aria-label="이전 페이지">
          <ChevronLeft size={14} />
        </button>
        <span className="px-2 font-mono tabular-nums text-ink">
          {page} / {Math.max(1, pageCount)}
        </span>
        <button className="btn btn-ghost h-7 px-1.5" onClick={() => onChange(page + 1)} disabled={page >= pageCount} aria-label="다음 페이지">
          <ChevronRight size={14} />
        </button>
        <button className="btn btn-ghost h-7 px-1.5" onClick={() => onChange(pageCount)} disabled={page >= pageCount} aria-label="마지막 페이지">
          <ChevronsRight size={14} />
        </button>
      </div>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-faint">{label}</span>
      {children}
    </label>
  );
}

export function KeyValue({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 text-xs">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className={`min-w-0 break-all text-right text-ink ${mono ? "font-mono" : ""}`}>{children}</dd>
    </div>
  );
}

export function DirectionBadge({ src, dst, compact = false }: { src: string; dst: string; compact?: boolean }) {
  const dir = directionOf(src, dst);
  if (!dir) return null;
  const m = DIRECTION_META[dir];
  return (
    <span
      title={m.desc}
      className={`inline-flex shrink-0 items-center whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset ${m.className}`}
    >
      {compact ? m.short : m.label}
    </span>
  );
}
