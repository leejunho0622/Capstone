import { useId, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { CountPoint } from "../api/types";
import { ATTACK_ORDER, ATTACK_TYPES, normalizeAttackKey } from "../lib/attackTypes";
import { EmptyState } from "./ui";

/* =========================================================
   차트 (dataviz 규칙: 얇은 선, 흐린 격자, 툴팁 기본 제공,
   범주색은 공격 유형에 '고정' 배정, 텍스트는 항상 본문색)
   ========================================================= */

const AXIS = { stroke: "rgb(var(--c-faint))", fontSize: 10 };
const GRID = "rgb(var(--c-line) / 0.6)";

function ChartTooltip({
  active,
  payload,
  label,
  unit = "건",
}: {
  active?: boolean;
  payload?: Array<{ value?: number | string; name?: string; color?: string }>;
  label?: string | number;
  unit?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-line bg-canvas/95 px-2.5 py-1.5 text-xs shadow-xl backdrop-blur">
      <p className="mb-0.5 text-[10px] text-muted">{label}</p>
      {payload.map((p, i) => (
        <p key={i} className="font-mono font-semibold tabular-nums text-ink">
          {Number(p.value ?? 0).toLocaleString()}
          <span className="ml-0.5 font-sans font-normal text-muted">{unit}</span>
        </p>
      ))}
    </div>
  );
}

export function TrendChart({
  data,
  height = 180,
  color = "var(--c-cat-1)",
  labelInterval = "preserveStartEnd",
}: {
  data: CountPoint[];
  height?: number;
  color?: string;
  labelInterval?: number | "preserveStartEnd";
}) {
  const gradientId = useId().replace(/:/g, "");
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -4, bottom: 0 }}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={GRID} vertical={false} />
          <XAxis dataKey="label" tickLine={false} axisLine={false} interval={labelInterval} {...AXIS} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={44} {...AXIS} />
          <Tooltip
            content={<ChartTooltip />}
            cursor={{ stroke: "rgb(var(--c-muted))", strokeDasharray: "3 3" }}
          />
          {/* 정수 건수라 곡선 보간은 없는 변동을 만들어 냄 → 직선 연결 */}
          <Area
            type="linear"
            dataKey="count"
            stroke={color}
            strokeWidth={2}
            fill={`url(#${gradientId})`}
            activeDot={{ r: 4, strokeWidth: 2, stroke: "rgb(var(--c-surface))" }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function WeeklyBars({ data, height = 180 }: { data: CountPoint[]; height?: number }) {
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -4, bottom: 0 }} barCategoryGap="28%">
          <CartesianGrid stroke={GRID} vertical={false} />
          <XAxis dataKey="label" tickLine={false} axisLine={false} {...AXIS} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={44} {...AXIS} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgb(var(--c-raised))" }} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
            {data.map((d, i) => (
              <Cell
                key={d.label}
                fill={i === data.length - 1 ? "rgb(var(--c-brand))" : "rgb(var(--c-brand) / 0.35)"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** 공격 유형 분포 도넛 + 범례(건수/비율 직접 표기) */
export function AttackDonut({
  data,
  onSelect,
}: {
  data: CountPoint[];
  onSelect?: (attackLabel: string) => void;
}) {
  const [hover, setHover] = useState<number | null>(null);

  const rows = useMemo(() => {
    const counts = new Map<string, number>();
    for (const d of data) {
      const k = normalizeAttackKey(d.label);
      if (k === "Normal") continue;
      counts.set(k, (counts.get(k) ?? 0) + d.count);
    }
    return ATTACK_ORDER.map((k) => ({
      key: k,
      label: ATTACK_TYPES[k].label,
      labelKo: ATTACK_TYPES[k].labelKo,
      color: ATTACK_TYPES[k].color,
      count: counts.get(k) ?? 0,
    }));
  }, [data]);

  const total = rows.reduce((s, r) => s + r.count, 0);
  if (total === 0) {
    return <EmptyState title="탐지된 공격이 없습니다" desc="선택한 기간에 공격으로 분류된 트래픽이 없습니다." />;
  }
  const active = hover !== null ? rows[hover] : null;

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row">
      <div className="relative h-[168px] w-[168px] shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={rows.filter((r) => r.count > 0)}
              dataKey="count"
              nameKey="label"
              innerRadius={56}
              outerRadius={80}
              paddingAngle={1.5}
              stroke="rgb(var(--c-surface))"
              strokeWidth={2}
              isAnimationActive={false}
              onMouseLeave={() => setHover(null)}
            >
              {rows
                .filter((r) => r.count > 0)
                .map((r) => (
                  <Cell
                    key={r.key}
                    fill={r.color}
                    opacity={active && active.key !== r.key ? 0.35 : 1}
                    onMouseEnter={() => setHover(rows.indexOf(r))}
                    onClick={() => onSelect?.(r.label)}
                    style={{ cursor: onSelect ? "pointer" : "default", outline: "none" }}
                  />
                ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[10px] text-muted">{active ? active.label : "전체"}</span>
          <span className="font-mono text-xl font-semibold tabular-nums text-ink">
            {(active ? active.count : total).toLocaleString()}
          </span>
          <span className="text-[10px] text-muted">
            {active ? `${((active.count / total) * 100).toFixed(1)}%` : "건"}
          </span>
        </div>
      </div>

      <ul className="w-full min-w-0 space-y-1">
        {rows.map((r, i) => {
          const pct = total ? r.count / total : 0;
          return (
            <li key={r.key}>
              <button
                type="button"
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
                onClick={() => onSelect?.(r.label)}
                disabled={!onSelect}
                className={`grid w-full grid-cols-[auto_1fr_auto_auto] items-center gap-2 rounded px-2 py-1 text-left text-xs transition ${
                  hover === i ? "bg-raised" : ""
                } ${onSelect ? "cursor-pointer" : "cursor-default"}`}
              >
                <span className="h-2.5 w-2.5 rounded-sm" style={{ background: r.color }} aria-hidden />
                <span className="truncate text-ink" title={r.labelKo}>
                  {r.label}
                </span>
                <span className="font-mono tabular-nums text-ink">{r.count.toLocaleString()}</span>
                <span className="w-12 text-right font-mono tabular-nums text-muted">
                  {(pct * 100).toFixed(1)}%
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** 작은 스파크라인 (KPI 카드용) */
export function Sparkline({ data, color = "var(--c-cat-1)" }: { data: number[]; color?: string }) {
  if (data.length < 2) return null;
  const max = Math.max(1, ...data);
  const w = 100;
  const h = 28;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * (h - 2) - 1}`);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-7 w-full" aria-hidden>
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
