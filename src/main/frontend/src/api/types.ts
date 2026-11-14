/* =========================================================
   백엔드 응답 DTO (com.cju.capstone.dto.* 와 1:1)
   - LocalDateTime 은 "2026-11-03T13:58:12" 형태의 문자열
   - JSON 컬럼(response_guide, risk_breakdown)은 객체 그대로 내려옴
   ========================================================= */

/** GET /api/dashboard/summary */
export interface DashboardSummaryDto {
  totalFlows: number;
  todayFlows: number;
  todayAttacks: number;
  activeAttacks: number;
  realtimeAttack: boolean;
  avgRisk: number;
  maxRisk: number;
}

/** GET /api/dashboard/attack-types?period=all|today */
export interface AttackTypeDto {
  type: string;
  count: number;
}

/** GET /api/dashboard/timeline  (최근 7일, day = "MM/dd") */
export interface TimelineDto {
  day: string;
  count: number;
}

/** GET /api/dashboard/realtime  (최근 24시간, hour = 0~23) */
export interface RealtimeDto {
  hour: number;
  count: number;
}

export interface TriageDto {
  attackId: number;
  status: "NEW" | "ACK" | "RESOLVED" | "FALSE_POSITIVE";
  note: string | null;
  assignee: string | null;
  updatedAt: string | null;
}

/** GET /api/incidents  (attack_events 1행 = 공격 1건) */
export interface IncidentDto {
  id: number;
  attackType: string;
  attackSubtype: string | null;
  groupKey: string | null;
  srcIp: string | null;
  destIp: string | null;
  destPort: number | null;
  uniqueSrcIps: number;
  uniqueDstIps: number;
  uniqueDstPorts: number;
  firstSeen: string | null;
  lastSeen: string | null;
  flowCount: number;
  maxRisk: number;
  avgRisk: number;
  eventRisk: number;
  action: string | null;
  actionDetail: string | null;
  responseGuide: unknown;
  state: string | null; // open | closed
  triage: TriageDto | null;
}

export interface AiSummaryDto {
  prediction: string | null;
  attackType: string | null;
  attackSubtype: string | null;
  confidence: number | null;
  riskScore: number | null;
  action: string | null;
}

/** GET /api/flows 목록 항목 */
export interface FlowListItemDto {
  flowId: number;
  srcIp: string | null;
  destIp: string | null;
  srcPort: number | null;
  destPort: number | null;
  protocol: string | null;
  startTime: string | null;
  endTime: string | null;
  attackId: number | null;
  synCount: number;
  ackCount: number;
  finCount: number;
  rstCount: number;
  pshCount: number;
  urgCount: number;
  ai: AiSummaryDto | null;
}

export interface AiResultDto {
  id: number;
  flowId: number;
  modelName: string | null;
  modelVersion: string | null;
  prediction: string | null;
  attackType: string | null;
  attackSubtype: string | null;
  confidence: number | null;
  riskScore: number | null;
  action: string | null;
  actionDetail: string | null;
  responseGuide: unknown;
  riskBreakdown: unknown;
  falsePositive: boolean;
  analyzedAt: string | null;
}

/** GET /api/flows/{flowId} */
export interface FlowDetailDto extends Omit<FlowListItemDto, "ai"> {
  bytesToServer: number | null;
  bytesToClient: number | null;
  pktsToServer: number | null;
  pktsToClient: number | null;
  idsSeverity: number | null;
  eventType: string | null;
  idsRuleId: string | null;
  aiResult: AiResultDto | null;
}

/** Spring Data Page<T> 직렬화 형식 (PagedModel 형식도 지원) */
export interface SpringPage<T> {
  content: T[];
  totalElements?: number;
  totalPages?: number;
  number?: number;
  size?: number;
  page?: { size: number; number: number; totalElements: number; totalPages: number };
}

/* =========================================================
   화면에서 쓰는 정규화된 타입
   ========================================================= */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TriageStatus = TriageDto["status"];

export interface TcpFlags {
  syn: number;
  ack: number;
  fin: number;
  rst: number;
  psh: number;
  urg: number;
}

export interface Flow {
  flowId: string;
  srcIp: string;
  destIp: string;
  srcPort: number | null;
  destPort: number | null;
  protocol: string;
  startTime: Date | null;
  endTime: Date | null;
  attackId: string | null;
  flags: TcpFlags;
}

export interface FlowDetail extends Flow {
  bytesToServer: number | null;
  bytesToClient: number | null;
  pktsToServer: number | null;
  pktsToClient: number | null;
  idsSeverity: number | null;
  eventType: string | null;
  idsRuleId: string | null;
}

export interface AiVerdict {
  id: number;
  modelName: string;
  modelVersion: string;
  prediction: string;
  attackType: string;
  attackSubtype: string | null;
  /** 0~1 */
  confidence: number;
  /** 0~100 */
  riskScore: number;
  action: string;
  actionDetail: string;
  responseGuide: ResponseGuide | null;
  riskBreakdown: RiskBreakdown | null;
  falsePositive: boolean;
  analyzedAt: Date | null;
  isAttack: boolean;
}

/** risk_scorer.py 가 남기는 위험도 산출 근거 */
export interface RiskBreakdown {
  base?: number;
  components?: Record<string, number>;
  multipliers?: Record<string, number>;
  inputs?: Record<string, unknown>;
  [key: string]: unknown;
}

/** response_playbook.py 가 남기는 대응 가이드 (형식이 바뀌어도 화면이 깨지지 않도록 느슨하게) */
export interface ResponseGuide {
  config_files?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface TriageInfo {
  status: TriageStatus;
  note: string;
  assignee: string;
  updatedAt: Date | null;
}

/** 경보 = attack_events 의 공격 1건 */
export interface Alert {
  id: string;
  attackType: string;
  attackSubtype: string | null;
  groupKey: string | null;
  srcIp: string;
  destIp: string;
  destPort: number | null;
  uniqueSrcIps: number;
  uniqueDstIps: number;
  uniqueDstPorts: number;
  firstSeen: Date | null;
  lastSeen: Date | null;
  flowCount: number;
  maxRisk: number;
  avgRisk: number;
  /** 공격 단위 종합 위험도 = 0.7*max + 0.2*avg + 규모 보너스 */
  riskScore: number;
  severity: Severity;
  action: string;
  actionDetail: string;
  responseGuide: ResponseGuide | null;
  /** 파이프라인 기준 진행 중 여부 (attack_events.status = 'open') */
  active: boolean;
  triage: TriageInfo | null;
}

export interface FlowWithVerdict {
  flow: Flow;
  ai: Pick<AiVerdict, "prediction" | "attackType" | "attackSubtype" | "confidence" | "riskScore" | "action" | "isAttack"> | null;
}

export interface Summary {
  totalFlows: number;
  todayFlows: number;
  todayAttacks: number;
  activeAttacks: number;
  realtimeAttack: boolean;
  avgRisk: number;
  maxRisk: number;
}

export interface CountPoint {
  label: string;
  count: number;
}

/* =========================================================
   공격 연관 분석 / AI 판정 품질
   ========================================================= */

/** GET /api/chains */
export interface ChainDto {
  id: string;
  srcIp: string;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  flowCount: number;
  targetCount: number;
  targets: string[];
  stages: string[];
  highestStage: string;
  escalated: boolean;
  active: boolean;
  maxEventRisk: number;
  chainRisk: number;
  events: Array<{
    id: number;
    attackType: string;
    attackSubtype: string | null;
    stage: string;
    firstSeen: string;
    lastSeen: string | null;
    destIp: string | null;
    destPort: number | null;
    flowCount: number;
    eventRisk: number;
    state: string | null;
  }>;
}

export interface ChainEvent {
  id: string;
  attackType: string;
  attackSubtype: string | null;
  stage: string;
  firstSeen: Date | null;
  lastSeen: Date | null;
  destIp: string;
  destPort: number | null;
  flowCount: number;
  riskScore: number;
  active: boolean;
}

export interface Chain {
  id: string;
  srcIp: string;
  firstSeen: Date | null;
  lastSeen: Date | null;
  eventCount: number;
  flowCount: number;
  targetCount: number;
  targets: string[];
  stages: string[];
  highestStage: string;
  escalated: boolean;
  active: boolean;
  maxEventRisk: number;
  chainRisk: number;
  events: ChainEvent[];
}

/** GET /api/ai/quality */
export interface AiQuality {
  days: number;
  analyzedFlows: number;
  attackFlows: number;
  avgAttackConfidence: number;
  falsePositiveFlows: number;
  reviewedIncidents: number;
  falsePositiveIncidents: number;
  types: Array<{
    type: string;
    flows: number;
    avgConfidence: number;
    avgRisk: number;
    falsePositiveFlows: number;
    incidents: number;
    resolved: number;
    falsePositive: number;
    inProgress: number;
    untouched: number;
  }>;
  confidenceHistogram: Array<{ from: number; to: number; count: number }>;
  riskHistogram: Array<{ from: number; to: number; count: number }>;
  models: Array<{ modelName: string; modelVersion: string; flows: number }>;
}

/** GET /api/ai/ids-comparison */
export interface IdsComparisonDto {
  days: number;
  flows: { both: number; aiOnly: number; idsOnly: number; neither: number };
  incidents: { total: number; idsDetected: number; aiOnly: number };
  types: Array<{ type: string; aiFlows: number; idsAlsoFlows: number; incidents: number; idsDetectedIncidents: number }>;
  aiOnlyIncidents: IncidentDto[];
  idsOnlyFlows: FlowListItemDto[];
}

export interface IdsComparison extends Omit<IdsComparisonDto, "aiOnlyIncidents" | "idsOnlyFlows"> {
  aiOnlyIncidents: Alert[];
  idsOnlyFlows: FlowWithVerdict[];
}

export interface LatencyStats {
  count: number;
  excluded: number;
  avg: number;
  p50: number;
  p90: number;
  p95: number;
  max: number;
  buckets: Array<{ label: string; fromSec: number; toSec: number; count: number }>;
}

/** GET /api/ai/latency */
export interface Latency {
  days: number;
  incident: LatencyStats;
  flow: LatencyStats;
}
