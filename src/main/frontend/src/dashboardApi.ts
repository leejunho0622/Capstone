const API_BASE = "";

export interface SummaryData {
  attackCount: number;
  dangerLevel: string;
  averageRisk: number;
  realtimeStatus: string;
}

export interface ChartItem {
  name: string;
  value: number;
}

export type AttackTypePeriod = "all" | "week";

export interface TimelineItem {
  t: string;
  v: number;
}

export interface AlertItem {
  level: string;
  ip: string;
  flowId: string;
  srcIp: string;
  srcPort: string | number;
  destIp: string;
  destPort: string | number;
  prediction: string;
  action: string;
  riskScore: string | number;
}

export interface TrafficItem {
  flowId: string;
  time: string;
  srcIp: string;
  dstIp: string;
  port: number;
  protocol: string;
  flag: string;
  result: string;
  attackType: string;
  startTime: string;
  endTime: string;
}

export interface TrafficDetail {
  flowId: string;
  srcIp: string;
  dstIp: string;
  srcPort: string | number;
  dstPort: string | number;
  protocol: string;
  startTime: string;
  endTime: string;
  tcpFlags: string;
  tcpFlagCounts: TrafficTcpFlagCounts;
  aiResult: TrafficAiResult | null;
}

export interface TrafficTcpFlagCounts {
  syn: number;
  ack: number;
  fin: number;
  rst: number;
  psh: number;
  urg: number;
}

export interface TrafficAiResult {
  id?: string | number;
  modelName: string;
  prediction: string;
  attackType: string;
  confidence: number | string;
  riskScore: number | string;
  action: string;
  actionDetail: string;
  analyzedAt: string;
}

export interface TrafficPageResult {
  items: TrafficItem[];
  totalPages: number;
  hasNext: boolean;
}

export interface AIResult {
  risk: string;
  detect: string;
  percent: string;
}

interface AiResultRow {
  prediction?: string;
  attackType?: string;
  riskScore?: string | number;
  action?: string;
  actionDetail?: string;
}

async function request<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${url}`);

    if (!res.ok) {
      throw new Error(`API Error: ${res.status}`);
    }

    return await res.json();
  } catch (err) {
    console.error("API request failed:", err);
    return null;
  }
}

function convertRisk(level?: string): string {
  if (level === "HIGH") return "위험";
  if (level === "MEDIUM") return "주의";
  return "안전";
}

function getCount(row: any, key: string): number {
  const value = row[key];
  return typeof value === "number" ? value : Number(value ?? 0);
}

function getTcpFlagCounts(row: any): TrafficTcpFlagCounts {
  return {
    syn: getCount(row, "synCount"),
    ack: getCount(row, "ackCount"),
    fin: getCount(row, "finCount"),
    rst: getCount(row, "rstCount"),
    psh: getCount(row, "pshCount"),
    urg: getCount(row, "urgCount"),
  };
}

function formatTcpFlags(row: any): string {
  const counts = getTcpFlagCounts(row);
  const flagCounts: Array<[string, number]> = [
    ["SYN", counts.syn],
    ["ACK", counts.ack],
    ["FIN", counts.fin],
    ["RST", counts.rst],
    ["PSH", counts.psh],
    ["URG", counts.urg],
  ];
  const flags = flagCounts
    .filter(([, count]) => count > 0)
    .map(([name, count]) => `${name}:${count}`);

  return flags.length > 0 ? flags.join(" ") : row.flag ?? row.tcpFlags ?? "-";
}

function getFlowLevel(row: any): string {
  if (row.level || row.risk) {
    return convertRisk(row.level ?? row.risk);
  }

  const synCount = getCount(row, "synCount");
  const rstCount = getCount(row, "rstCount");
  const finCount = getCount(row, "finCount");

  if (synCount >= 1 || rstCount >= 1) return "주의";
  if (finCount >= 1) return "알림";
  return "정상";
}

function getPrediction(row: any): string {
  return String(
    row.prediction ??
      row.pridiction ??
      row.attackType ??
      row.result ??
      row.aiResult ??
      "-"
  );
}

function getFirstAiResult(row: any): AiResultRow | null {
  const direct = row.aiResult ?? row.ai_result ?? row.resultDetail;
  if (direct && typeof direct === "object") return direct;

  const list = row.aiResults ?? row.ai_results ?? row.results;
  if (Array.isArray(list) && list.length > 0) return list[0];

  return null;
}
export async function fetchSummary(): Promise<SummaryData | null> {
  const json: any = await request("/api/dashboard/summary");
  if (!json) return null;

  return {
    attackCount: json.todayAttacks ?? 0,
    dangerLevel: json.avgRisk >= 70 ? "위험" : "주의",
    averageRisk: Math.round(json.avgRisk ?? 0),
    realtimeStatus: json.realtimeAttack ? "ATTACK" : "NORMAL",
  };
}

export async function fetchAttackTypes(
  period: AttackTypePeriod = "all"
): Promise<ChartItem[]> {
  const params = new URLSearchParams({ period });
  const res = await fetch(`${API_BASE}/api/dashboard/attack-types?${params}`);

  if (!res.ok) {
    throw new Error(`Attack types API Error: ${res.status}`);
  }

  const json: any[] = await res.json();

  return json.map((item) => ({
    name: item.attackType ?? item.type ?? "-",
    value: Number(item.count ?? 0),
  }));
}

export async function fetchTimeline():Promise<TimelineItem[]>{
  const json:any[]|null=
      await request(
          "/api/dashboard/timeline"
      );

  if(!json)
    return [];

  return json.map(
      item=>({
        t:item.day ?? item.t,
        v:item.count ?? item.v ?? 0
      })
  );
}

export async function fetchAlerts():Promise<AlertItem[]>{

  const json:any=
      await request(
          "/api/dashboard/alerts"
      );

  if(!json)
    return [];

  const rows=
      json.content ??
      [];

  return rows.map(
      (row:any)=>{

        const flow=row.flow;
        const ai=row.aiResult;

        return{

          level:getFlowLevel(flow),

          ip:
              `${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort}`,

          flowId:
              String(flow.flowId),

          srcIp:flow.srcIp,
          srcPort:flow.srcPort,

          destIp:flow.destIp,
          destPort:flow.destPort,

          prediction:
              ai?.attackType ??
              ai?.prediction ??
              "-",

          action:
              ai?.action ??
              "-",

          riskScore:
              ai?.riskScore ??
              "-"
        };
      }
  );
}

export async function fetchAllAlerts():Promise<AlertItem[]>{

  let page=0;

  const size=100;

  const all:AlertItem[]=[];

  while(true){

    const json:any=
        await request(
            `/api/dashboard/alerts?page=${page}&size=${size}`
        );

    if(!json)
      break;

    const rows=
        json.content ??
        [];

    if(rows.length===0)
      break;

    const mapped=
        rows.map(
            (row:any)=>{

              const flow=
                  row.flow;

              const ai=
                  row.aiResult;

              return{

                level:
                    getFlowLevel(flow),

                ip:
                    `${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort}`,

                flowId:
                    String(flow.flowId),

                srcIp:flow.srcIp,
                srcPort:flow.srcPort,

                destIp:flow.destIp,
                destPort:flow.destPort,

                prediction:
                    ai?.attackType ??
                    ai?.prediction ??
                    "-",

                action:
                    ai?.action ??
                    "-",

                riskScore:
                    ai?.riskScore ??
                    "-"

              };

            }
        );

    all.push(
        ...mapped
    );

    if(
        json.last===true
    )
      break;

    page++;

  }

  return all;
}

function toTrafficItems(rows: any[]): TrafficItem[] {
  return rows.map((row: any) => {
    const aiResult = getFirstAiResult(row);
    const prediction = aiResult ? getPrediction(aiResult) : getPrediction(row);

    return {
      flowId: String(row.flowId ?? row.id ?? ""),
      time: row.startTime ? row.startTime.split("T")[1] ?? row.startTime : "-",
      srcIp: row.srcIp ?? row.sourceIp ?? "-",
      dstIp: row.destIp ?? row.dstIp ?? row.destinationIp ?? "-",
      port: row.destPort ?? row.destport ?? row.dstPort ?? row.port ?? 0,
      protocol: row.protocol ?? "-",
      flag: formatTcpFlags(row),
      result: prediction === "-" ? "분석 완료" : prediction,
      attackType:
        aiResult?.attackType ?? row.attackType ?? row.type ?? prediction,
      startTime: row.startTime ?? "-",
      endTime: row.endTime ?? "-",
    };
  });
}

function toTrafficAiResult(row: any): TrafficAiResult | null {
  if (!row || typeof row !== "object") return null;

  return {
    id: row.id,
    modelName: row.modelName ?? "-",
    prediction: row.prediction ?? "-",
    attackType: row.attackType ?? "-",
    confidence: row.confidence ?? "-",
    riskScore: row.riskScore ?? "-",
    action: row.action ?? "-",
    actionDetail: row.actionDetail ?? "-",
    analyzedAt: row.analyzedAt ?? "-",
  };
}

function getActiveTcpFlags(row:any):string{

  const flags:string[]=[];

  if((row.synCount??0)>0) flags.push("SYN");
  if((row.ackCount??0)>0) flags.push("ACK");
  if((row.finCount??0)>0) flags.push("FIN");
  if((row.rstCount??0)>0) flags.push("RST");
  if((row.pshCount??0)>0) flags.push("PSH");
  if((row.urgCount??0)>0) flags.push("URG");

  return flags.join(", ");
}

function toTrafficDetail(
    row:any,
    aiResult?:any
):TrafficDetail{

  const embeddedAiResult =
      getFirstAiResult(row);

  return {

    flowId:
        String(
            row.flowId ??
            row.id ??
            ""
        ),

    srcIp:
        row.srcIp ??
        row.sourceIp ??
        "-",

    dstIp:
        row.destIp ??
        row.dstIp ??
        row.destinationIp ??
        "-",

    srcPort:
        row.srcPort ??
        row.sourcePort ??
        row.sport ??
        "-",

    dstPort:
        row.destPort ??
        row.destport ??
        row.dstPort ??
        row.port ??
        "-",

    protocol:
        row.protocol ??
        "-",

    startTime:
        row.startTime ??
        "-",

    endTime:
        row.endTime ??
        "-",

    tcpFlags:
        getActiveTcpFlags(row),

    tcpFlagCounts:
        getTcpFlagCounts(row),

    aiResult:
        toTrafficAiResult(
            aiResult ??
            embeddedAiResult
        )
  };
}

export async function fetchTraffic(): Promise<TrafficItem[]> {

  const json:any =
      await request(
          "/api/flows"
      );

  if(!json)
    return [];

  const rows =
      Array.isArray(json)
          ? json
          : json.content ??
          [];

  return toTrafficItems(rows);
}

export async function fetchTrafficDetail(
  flowId: string | number
): Promise<TrafficDetail | null> {
  const detail: any = await request(`/api/flows/${flowId}`);
  if (!detail) return null;

  if (detail.aiResult || detail.ai_result || detail.resultDetail) {
    return toTrafficDetail(detail);
  }

  const aiResults: any[] | null = await request(
    `/api/flows/${flowId}/ai-results`
  );

  return toTrafficDetail(
    detail,
    Array.isArray(aiResults) && aiResults.length > 0 ? aiResults[0] : null
  );
}

export async function getAIResult(flowId: number): Promise<AIResult | null> {
  const json: any = await request(`/api/flows/${flowId}/ai-results`);
  if (!json || json.length === 0) return null;

  const result = json[0];
  return {
    risk: result.riskScore > 60 ? "위험" : "보통",
    detect: result.attackType,
    percent: `${(result.confidence * 100).toFixed(1)}%`,
  };
}

export async function fetchRealtimeTimeline():Promise<TimelineItem[]>{
  const json:any[]|null=await request("/api/dashboard/realtime");

  if(!json) return [];

  return json.map(item=>({
    t:`${item.hour}시`,
    v:item.count??0
  }));
}