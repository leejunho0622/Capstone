import { API_BASE, http } from "./http";
import type {
  IdsComparison,
  IdsComparisonDto,
  Latency,
  AiQuality,
  Chain,
  ChainDto,
  AiResultDto,
  AiSummaryDto,
  AiVerdict,
  Alert,
  AttackTypeDto,
  CountPoint,
  DashboardSummaryDto,
  Flow,
  FlowDetail,
  FlowDetailDto,
  FlowListItemDto,
  FlowWithVerdict,
  IncidentDto,
  RealtimeDto,
  ResponseGuide,
  RiskBreakdown,
  SpringPage,
  Summary,
  TimelineDto,
  TriageDto,
  TriageInfo,
  TriageStatus,
} from "./types";
import { normalizeAttackKey } from "../lib/attackTypes";
import { severityFromScore } from "../lib/severity";

export type { TriageStatus } from "./types";

/* =========================================================
   API 함수 모음
   - 모든 응답은 여기서 '화면용 타입'으로 정규화합니다.
   - 컴포넌트는 백엔드 필드명을 직접 알 필요가 없습니다.
   ========================================================= */

// ---------- 공통 변환 ----------

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function num(value: unknown, fallback = 0): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

/** JSON 컬럼이 문자열로 올 수도 있어 둘 다 처리 */
function jsonObject<T>(value: unknown): T | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" ? (parsed as T) : null;
    } catch {
      return null;
    }
  }
  return typeof value === "object" ? (value as T) : null;
}

function isAttackVerdict(prediction: string | null | undefined, attackType: string | null | undefined) {
  const key = normalizeAttackKey(attackType ?? prediction);
  if (String(prediction ?? "").toLowerCase() === "attack") return true;
  return key !== "Normal" && key !== "Unknown";
}

function toPage<D, T>(raw: SpringPage<D> | D[], map: (d: D) => T): PageResult<T> {
  if (Array.isArray(raw)) {
    return { items: raw.map(map), page: 0, size: raw.length, totalElements: raw.length, totalPages: 1 };
  }
  const meta = raw.page ?? raw;
  return {
    items: (raw.content ?? []).map(map),
    page: num(meta.number),
    size: num(meta.size),
    totalElements: num(meta.totalElements),
    totalPages: Math.max(1, num(meta.totalPages, 1)),
  };
}

export interface PageResult<T> {
  items: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

// ---------- 플로우 ----------

function toFlow(dto: FlowListItemDto | FlowDetailDto): Flow {
  return {
    flowId: String(dto.flowId),
    srcIp: dto.srcIp ?? "-",
    destIp: dto.destIp ?? "-",
    srcPort: dto.srcPort ?? null,
    destPort: dto.destPort ?? null,
    protocol: (dto.protocol ?? "-").toUpperCase(),
    startTime: parseDate(dto.startTime),
    endTime: parseDate(dto.endTime),
    attackId: dto.attackId !== null && dto.attackId !== undefined ? String(dto.attackId) : null,
    flags: {
      syn: num(dto.synCount),
      ack: num(dto.ackCount),
      fin: num(dto.finCount),
      rst: num(dto.rstCount),
      psh: num(dto.pshCount),
      urg: num(dto.urgCount),
    },
  };
}

function toConfidence(v: unknown) {
  const c = num(v);
  return c > 1 ? c / 100 : c; // 0~100 으로 들어오는 경우 방어
}

function toAiSummary(dto: AiSummaryDto | null | undefined): FlowWithVerdict["ai"] {
  if (!dto) return null;
  return {
    prediction: dto.prediction ?? "-",
    attackType: dto.attackType ?? "-",
    attackSubtype: dto.attackSubtype ?? null,
    confidence: toConfidence(dto.confidence),
    riskScore: round1(num(dto.riskScore)),
    action: dto.action ?? "-",
    isAttack: isAttackVerdict(dto.prediction, dto.attackType),
  };
}

export function toVerdict(dto: AiResultDto | null | undefined): AiVerdict | null {
  if (!dto) return null;
  return {
    id: num(dto.id),
    modelName: dto.modelName ?? "-",
    modelVersion: dto.modelVersion ?? "-",
    prediction: dto.prediction ?? "-",
    attackType: dto.attackType ?? "-",
    attackSubtype: dto.attackSubtype ?? null,
    confidence: toConfidence(dto.confidence),
    riskScore: round1(num(dto.riskScore)),
    action: dto.action ?? "-",
    actionDetail: dto.actionDetail ?? "",
    responseGuide: jsonObject<ResponseGuide>(dto.responseGuide),
    riskBreakdown: jsonObject<RiskBreakdown>(dto.riskBreakdown),
    falsePositive: Boolean(dto.falsePositive),
    analyzedAt: parseDate(dto.analyzedAt),
    isAttack: isAttackVerdict(dto.prediction, dto.attackType),
  };
}

// ---------- 경보(공격 단위) ----------

function toTriage(dto: TriageDto | null | undefined): TriageInfo | null {
  if (!dto) return null;
  return {
    status: dto.status,
    note: dto.note ?? "",
    assignee: dto.assignee ?? "",
    updatedAt: parseDate(dto.updatedAt),
  };
}

export function toAlert(dto: IncidentDto): Alert {
  const riskScore = round1(num(dto.eventRisk));
  return {
    id: String(dto.id),
    attackType: dto.attackType ?? "Unknown",
    attackSubtype: dto.attackSubtype ?? null,
    groupKey: dto.groupKey ?? null,
    srcIp: dto.srcIp ?? "-",
    destIp: dto.destIp ?? "-",
    destPort: dto.destPort ?? null,
    uniqueSrcIps: num(dto.uniqueSrcIps, 1),
    uniqueDstIps: num(dto.uniqueDstIps, 1),
    uniqueDstPorts: num(dto.uniqueDstPorts, 1),
    firstSeen: parseDate(dto.firstSeen),
    lastSeen: parseDate(dto.lastSeen),
    flowCount: num(dto.flowCount),
    maxRisk: round1(num(dto.maxRisk)),
    avgRisk: round1(num(dto.avgRisk)),
    riskScore,
    severity: severityFromScore(riskScore),
    action: dto.action ?? "-",
    actionDetail: dto.actionDetail ?? "",
    responseGuide: jsonObject<ResponseGuide>(dto.responseGuide),
    active: String(dto.state ?? "").toLowerCase() === "open",
    triage: toTriage(dto.triage),
  };
}

// ---------- 대시보드 ----------

export async function getSummary(signal?: AbortSignal): Promise<Summary> {
  const d = await http<DashboardSummaryDto>("/api/dashboard/summary", { signal });
  return {
    totalFlows: num(d.totalFlows),
    todayFlows: num(d.todayFlows),
    todayAttacks: num(d.todayAttacks),
    activeAttacks: num(d.activeAttacks),
    realtimeAttack: Boolean(d.realtimeAttack),
    avgRisk: round1(num(d.avgRisk)),
    maxRisk: round1(num(d.maxRisk)),
  };
}

export async function getAttackTypes(period: "all" | "today", signal?: AbortSignal): Promise<CountPoint[]> {
  const rows = await http<AttackTypeDto[]>("/api/dashboard/attack-types", { query: { period }, signal });
  return rows
    .filter((r) => normalizeAttackKey(r.type) !== "Normal")
    .map((r) => ({ label: r.type, count: num(r.count) }));
}

/** 최근 7일 일별 공격 건수 */
export async function getWeeklyTimeline(signal?: AbortSignal): Promise<CountPoint[]> {
  const rows = await http<TimelineDto[]>("/api/dashboard/timeline", { signal });
  return rows.map((r) => ({ label: r.day, count: num(r.count) }));
}

/** 최근 24시간 시간대별 공격 건수 (현재 시각이 맨 오른쪽) */
export async function getHourlyTimeline(signal?: AbortSignal): Promise<CountPoint[]> {
  const rows = await http<RealtimeDto[]>("/api/dashboard/realtime", { signal });
  const byHour = new Map(rows.map((r) => [num(r.hour), num(r.count)]));
  const nowHour = new Date().getHours();
  return Array.from({ length: 24 }, (_, i) => {
    const hour = (nowHour + 1 + i) % 24;
    return { label: `${String(hour).padStart(2, "0")}시`, count: byHour.get(hour) ?? 0 };
  });
}

// ---------- 경보 ----------

export async function getIncidents(
  params: { hours: number; size?: number },
  signal?: AbortSignal
): Promise<Alert[]> {
  const raw = await http<SpringPage<IncidentDto>>("/api/incidents", {
    query: { hours: params.hours, page: 0, size: params.size ?? 500 },
    signal,
  });
  return toPage(raw, toAlert).items;
}

export async function getIncident(id: string, signal?: AbortSignal): Promise<Alert> {
  return toAlert(await http<IncidentDto>(`/api/incidents/${encodeURIComponent(id)}`, { signal }));
}

export async function getIncidentFlows(
  id: string,
  page: number,
  size: number,
  signal?: AbortSignal
): Promise<PageResult<FlowWithVerdict>> {
  const raw = await http<SpringPage<FlowListItemDto>>(`/api/incidents/${encodeURIComponent(id)}/flows`, {
    query: { page, size },
    signal,
  });
  return toPage(raw, (row) => ({ flow: toFlow(row), ai: toAiSummary(row.ai) }));
}

export async function saveTriage(
  id: string,
  body: { status: TriageStatus; note: string; assignee: string }
): Promise<TriageInfo> {
  const dto = await http<TriageDto>(`/api/incidents/${encodeURIComponent(id)}/triage`, {
    method: "PUT",
    body,
  });
  return toTriage(dto)!;
}

// ---------- 트래픽 ----------

export interface FlowQuery {
  page: number; // 0부터
  size: number;
  q?: string;
  srcIp?: string;
  destIp?: string;
  port?: string;
  protocol?: string;
  attackType?: string;
  verdict?: "" | "attack" | "normal";
  hours?: number;
}

export async function getFlows(query: FlowQuery, signal?: AbortSignal): Promise<PageResult<FlowWithVerdict>> {
  const raw = await http<SpringPage<FlowListItemDto>>("/api/flows", { query: { ...query }, signal });
  return toPage(raw, (row) => ({ flow: toFlow(row), ai: toAiSummary(row.ai) }));
}

export async function getFlowDetail(
  flowId: string,
  signal?: AbortSignal
): Promise<{ flow: FlowDetail; ai: AiVerdict | null }> {
  const dto = await http<FlowDetailDto>(`/api/flows/${encodeURIComponent(flowId)}`, { signal });
  return {
    flow: {
      ...toFlow(dto),
      bytesToServer: dto.bytesToServer ?? null,
      bytesToClient: dto.bytesToClient ?? null,
      pktsToServer: dto.pktsToServer ?? null,
      pktsToClient: dto.pktsToClient ?? null,
      idsSeverity: dto.idsSeverity ?? null,
      eventType: dto.eventType ?? null,
      idsRuleId: dto.idsRuleId ?? null,
    },
    ai: toVerdict(dto.aiResult),
  };
}

export async function getAiHistory(flowId: string, signal?: AbortSignal): Promise<AiVerdict[]> {
  const rows = await http<AiResultDto[]>(`/api/flows/${encodeURIComponent(flowId)}/ai-results`, { signal });
  return rows.map(toVerdict).filter((v): v is AiVerdict => v !== null);
}

// ---------- 공격 연관 분석 ----------

export async function getChains(
  params: { hours: number; gap: number; minEvents?: number },
  signal?: AbortSignal
): Promise<Chain[]> {
  const rows = await http<ChainDto[]>("/api/chains", {
    query: { hours: params.hours, gap: params.gap, minEvents: params.minEvents ?? 2 },
    signal,
  });
  return rows.map((c) => ({
    id: c.id,
    srcIp: c.srcIp,
    firstSeen: parseDate(c.firstSeen),
    lastSeen: parseDate(c.lastSeen),
    eventCount: num(c.eventCount),
    flowCount: num(c.flowCount),
    targetCount: num(c.targetCount),
    targets: c.targets ?? [],
    stages: c.stages ?? [],
    highestStage: c.highestStage,
    escalated: Boolean(c.escalated),
    active: Boolean(c.active),
    maxEventRisk: round1(num(c.maxEventRisk)),
    chainRisk: round1(num(c.chainRisk)),
    events: (c.events ?? []).map((e) => ({
      id: String(e.id),
      attackType: e.attackType,
      attackSubtype: e.attackSubtype ?? null,
      stage: e.stage,
      firstSeen: parseDate(e.firstSeen),
      lastSeen: parseDate(e.lastSeen),
      destIp: e.destIp ?? "-",
      destPort: e.destPort ?? null,
      flowCount: num(e.flowCount),
      riskScore: round1(num(e.eventRisk)),
      active: String(e.state ?? "").toLowerCase() === "open",
    })),
  }));
}

// ---------- AI 판정 품질 ----------

export async function getAiQuality(days: number, signal?: AbortSignal): Promise<AiQuality> {
  return http<AiQuality>("/api/ai/quality", { query: { days }, signal });
}

/** 재학습용 오탐 CSV 다운로드 주소 (브라우저가 직접 받음) */
export function falsePositiveCsvUrl(days: number): string {
  return `${API_BASE}/api/ai/false-positives.csv?days=${days}`;
}

// ---------- 탐지 성능 ----------

export async function getIdsComparison(days: number, signal?: AbortSignal): Promise<IdsComparison> {
  const d = await http<IdsComparisonDto>("/api/ai/ids-comparison", { query: { days }, signal });
  return {
    ...d,
    aiOnlyIncidents: (d.aiOnlyIncidents ?? []).map(toAlert),
    idsOnlyFlows: (d.idsOnlyFlows ?? []).map((row) => ({ flow: toFlow(row), ai: toAiSummary(row.ai) })),
  };
}

export async function getLatency(days: number, signal?: AbortSignal): Promise<Latency> {
  return http<Latency>("/api/ai/latency", { query: { days }, signal });
}
