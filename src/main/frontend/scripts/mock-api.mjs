#!/usr/bin/env node
/* =========================================================
   목업 API 서버 (DB/백엔드 없이 화면 시연·개발용)
   - 실제 Spring 백엔드와 같은 URL·응답 형식
   - 몇 초마다 새 공격이 생기고 진행 중 공격이 커지는 '실시간' 흉내
   실행:  npm run mock   →  http://localhost:8080
   (다른 터미널에서 npm run dev)
   외부 패키지 없이 Node 기본 모듈만 사용합니다.
   ========================================================= */
import http from "node:http";

const PORT = Number(process.env.MOCK_PORT ?? 8080);

// ---------- 결정적 난수 (매번 같은 시연 데이터) ----------
let seed = 20261103;
const rand = () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const between = (a, b) => a + rand() * (b - a);
const int = (a, b) => Math.floor(between(a, b + 1));

const pad = (n) => String(n).padStart(2, "0");
const iso = (d) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;

// ---------- 시나리오 (AI 파이프라인 문서 기준) ----------
const TYPES = [
  { type: "PortScan", subtypes: ["PortScan-TCP", "PortScan-UDP"], ports: [22, 80, 443, 3306, 8080], action: "monitor_src", risk: [28, 48], group: "src", flows: [20, 120], w: 5 },
  { type: "BruteForce", subtypes: ["BruteForce-SSH", "BruteForce-RDP", "BruteForce-MySQL", "BruteForce-FTP"], ports: [22, 3389, 3306, 21], action: "lockout", risk: [40, 79], group: "src", flows: [5, 60], w: 4 },
  { type: "SYNFlood", subtypes: ["SYNFlood-HTTP", "SYNFlood-SSH"], ports: [80, 22], action: "syn_cookie", risk: [42, 62], group: "dst", flows: [40, 300], w: 3 },
  { type: "DDoS", subtypes: ["DDoS-HTTPFlood", "DDoS-UDPFlood", "DDoS-Volumetric"], ports: [80, 443, 53, 8080], action: "rate_limit", risk: [45, 75], group: "dst", flows: [80, 600], w: 2 },
  { type: "NetworkScan", subtypes: ["NetworkScan-Sweep"], ports: [0, 80, 443], action: "monitor_src", risk: [30, 55], group: "src", flows: [15, 80], w: 2 },
  { type: "C2Beacon", subtypes: ["C2Beacon-HTTPS", "C2Beacon-DNS", "C2Beacon-HTTP"], ports: [443, 53, 80], action: "isolate_host", risk: [46, 73], group: "src", flows: [6, 24], w: 1 },
  { type: "UnknownAnomaly", subtypes: ["UnknownAnomaly"], ports: [8443, 9200, 6379], action: "monitor", risk: [30, 52], group: "src", flows: [1, 8], w: 1 },
];
const weighted = TYPES.flatMap((t) => Array(t.w).fill(t));

const EXTERNAL = ["203.0.113.5", "198.51.100.23", "45.33.32.156", "185.220.101.7", "91.240.118.172", "103.75.190.11", "194.26.29.113"];
const INTERNAL_SRC = ["192.168.0.14", "192.168.0.27", "10.10.0.45"];
const SERVERS = ["10.10.0.21", "10.10.0.22", "10.10.0.30", "192.168.0.100"];

const DETAIL = {
  lockout: (ip, sub) =>
    `고강도 ${sub.split("-")[1] ?? ""} 무차별 대입. 대상 계정을 즉시 잠그고 ${ip} 를 차단해야 한다.\n비밀번호 변경과 MFA 적용을 권고한다.`,
  syn_cookie: () => "SYN cookie 를 활성화하고 출발지별 SYN 속도 제한을 강화한다.",
  rate_limit: () => "rate limiting 을 적용하고, 지속되면 상위 회선(ISP)에 차단을 요청한다.",
  monitor_src: (ip) => `${ip} 를 집중 모니터링한다. 정찰이 지속되면 출발지를 차단한다.`,
  isolate_host: (ip) => `${ip} 호스트를 즉시 격리하고 악성코드 감염 여부를 조사한다.`,
  monitor: () => "학습되지 않은 이상 패턴. 모니터링하며 동일 패턴 반복 시 보안팀에 에스컬레이션한다.",
};

const GUIDE = {
  BruteForce: (sub) => ({
    summary: "인증 시도 제한과 출발지 차단을 함께 적용",
    config_files: sub.endsWith("SSH")
      ? [
          { path: "/etc/ssh/sshd_config", setting: "MaxAuthTries 3\nPermitRootLogin no", check: "test -f /etc/ssh/sshd_config && echo OK" },
          { path: "/etc/fail2ban/jail.local", setting: "[sshd]\nenabled = true\nmaxretry = 5\nbantime = 3600", check: "sudo fail2ban-client status sshd" },
        ]
      : [{ path: "/etc/mysql/mysql.conf.d/mysqld.cnf", setting: "bind-address = 127.0.0.1", check: "test -f /etc/mysql/mysql.conf.d/mysqld.cnf && echo OK" }],
    check_commands: ["sudo journalctl -u ssh --since '10 min ago' | grep Failed", "sudo ss -tnp state established"],
  }),
  SYNFlood: () => ({
    config_files: [{ path: "/etc/sysctl.d/99-syn-protect.conf", setting: "net.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 4096", check: "sysctl net.ipv4.tcp_syncookies" }],
    check_commands: ["ss -n state syn-recv | wc -l"],
  }),
  DDoS: () => ({
    config_files: [{ path: "/etc/nftables.conf", setting: "limit rate over 1000/second drop", check: "sudo nft list ruleset" }],
  }),
  PortScan: () => ({ config_files: [{ path: "/etc/nftables.conf", setting: "ip saddr <출발지> drop", check: "sudo nft list ruleset | grep saddr" }] }),
  NetworkScan: () => ({ config_files: [{ path: "/etc/nftables.conf", setting: "ip saddr <출발지> drop" }] }),
  C2Beacon: () => ({ config_files: [{ path: "/etc/nftables.conf", setting: "chain output { ip daddr <C&C> drop }" }], check_commands: ["sudo ss -tnp | grep ESTAB"] }),
  UnknownAnomaly: () => ({ config_files: [{ path: "/etc/suricata/suricata.yaml", setting: "탐지 임계값 조정" }] }),
};

// ---------- 데이터 저장소 ----------
const flows = []; // 최신이 앞
const ai = new Map(); // flowId → ai result
const events = []; // attack_events
const triage = new Map(); // attackId → triage
let flowSeq = 1_700_000;
let eventSeq = 1;

// Suricata 룰이 alert 를 낼 확률 (시그니처가 잘 잡는 유형 / 못 잡는 유형)
const IDS_RATE = { PortScan: 0.6, SYNFlood: 0.5, DDoS: 0.45, NetworkScan: 0.35, BruteForce: 0.25, C2Beacon: 0.05, UnknownAnomaly: 0.02 };
// 연결 종료 → AI 분석 지연(초): 대부분 flow-timeout(수~수십 초) + 처리
const latencySec = () => (rand() < 0.75 ? between(2, 25) : rand() < 0.85 ? between(25, 70) : between(70, 200));

function makeFlow({ src, dst, port, proto, at, attackId, attack, risk }) {
  const flowId = flowSeq++;
  const durMs = int(20, attack ? 900 : 8000);
  const endAt = new Date(at.getTime() - Math.round(latencySec() * 1000));
  const startAt = new Date(endAt.getTime() - durMs);
  const idsHit = attack ? rand() < (IDS_RATE[attack] ?? 0.2) : rand() < 0.02;
  const synOnly = attack === "SYNFlood" || attack === "PortScan";
  const f = {
    flowId,
    srcIp: src,
    destIp: dst,
    srcPort: int(30000, 65000),
    destPort: port,
    protocol: proto,
    startTime: iso(startAt),
    endTime: iso(endAt),
    attackId,
    synCount: proto === "TCP" ? (synOnly ? int(1, 3) : 1) : 0,
    ackCount: proto === "TCP" ? (synOnly ? 0 : int(2, 30)) : 0,
    finCount: proto === "TCP" && !synOnly ? 1 : 0,
    rstCount: attack === "PortScan" ? 1 : 0,
    pshCount: proto === "TCP" && !synOnly ? int(0, 12) : 0,
    urgCount: 0,
    bytesToServer: int(60, attack === "DDoS" ? 900000 : 9000),
    bytesToClient: synOnly ? 0 : int(60, 40000),
    pktsToServer: int(1, attack === "DDoS" ? 6000 : 40),
    pktsToClient: synOnly ? 0 : int(1, 40),
    idsSeverity: idsHit ? pick([1, 2, 3]) : null,
    eventType: idsHit ? "alert" : "flow",
    idsRuleId: idsHit ? String(int(2000000, 2100000)) : null,
  };
  flows.unshift(f);
  const isAttack = Boolean(attack);
  const rf = between(0.15, 0.4);
  const port_grade = [22, 23, 3389, 445].includes(port) ? "관리/원격접속" : [3306, 5432, 6379].includes(port) ? "DB" : [80, 443, 53].includes(port) ? "주요 서비스" : "기타";
  ai.set(flowId, {
    id: flowId * 2,
    flowId,
    modelName: "IF+RF+SEQ",
    modelVersion: "v1_cicids2017",
    prediction: isAttack && risk >= 40 ? "attack" : isAttack ? "suspicious" : "normal",
    attackType: attack ?? "Normal",
    attackSubtype: isAttack ? events.find((e) => e.id === attackId)?.attackSubtype ?? null : null,
    confidence: isAttack ? between(0.62, 0.98) : between(0.9, 0.995),
    riskScore: isAttack ? risk : between(0, 12),
    action: isAttack ? events.find((e) => e.id === attackId)?.action ?? "monitor" : "allow",
    actionDetail: isAttack ? events.find((e) => e.id === attackId)?.actionDetail ?? "" : "",
    responseGuide: isAttack ? events.find((e) => e.id === attackId)?.responseGuide ?? null : null,
    riskBreakdown: isAttack
      ? {
          base: +(risk / 100 / 1.3).toFixed(4),
          components: { rf: +rf.toFixed(4), anomaly: +between(0.03, 0.2).toFixed(4), sequence: +between(0, 0.1).toFixed(4), ids: f.idsSeverity ? 0.1 * ({ 1: 1, 2: 0.7, 3: 0.4 }[f.idsSeverity]) : 0 },
          multipliers: { type: pick([1.0, 1.05, 1.1]), port: { "관리/원격접속": 1.25, DB: 1.2, "주요 서비스": 1.1, 기타: 1.0 }[port_grade], recurrence: +(1 + Math.min(0.2, int(0, 4) * 0.04)).toFixed(2) },
          inputs: { dest_port: port, port_grade, recent_attacks_24h: int(0, 4), ids_severity: f.idsSeverity },
        }
      : null,
    falsePositive: false,
    featureVector: {
      flow_duration: +(durMs / 1000).toFixed(3),
      total_fwd_packets: f.pktsToServer,
      total_bwd_packets: f.pktsToClient,
      total_length_fwd: f.bytesToServer,
      total_length_bwd: f.bytesToClient,
      flow_bytes_per_s: +((f.bytesToServer + f.bytesToClient) / Math.max(0.001, durMs / 1000)).toFixed(1),
      flow_iat_mean: +((durMs / 1000) / Math.max(1, f.pktsToServer + f.pktsToClient - 1)).toFixed(4),
      syn_count: f.synCount,
      rst_count: f.rstCount,
      ack_count: f.ackCount,
      fin_count: f.finCount,
      fwd_bwd_ratio: +(f.pktsToServer / Math.max(1, f.pktsToClient)).toFixed(3),
      is_tcp: f.protocol === "TCP" ? 1 : 0,
      dest_port: port,
    },
    analyzedAt: iso(at),
  });
  return f;
}

function newEvent(at, opts = {}) {
  const t = opts.type ?? pick(weighted);
  const sub = pick(t.subtypes);
  const port = t.ports[t.subtypes.indexOf(sub)] ?? pick(t.ports);
  const src = t.type === "C2Beacon" ? pick(INTERNAL_SRC) : pick(EXTERNAL);
  const dst = t.type === "C2Beacon" ? pick(EXTERNAL) : pick(SERVERS);
  const e = {
    id: eventSeq++,
    attackType: t.type,
    attackSubtype: sub,
    groupKey: t.group === "dst" ? `dst:${dst}` : `src:${src}`,
    srcIp: src,
    destIp: dst,
    destPort: t.type === "NetworkScan" ? null : port,
    uniqueSrcIps: t.type === "DDoS" ? int(20, 140) : t.type === "SYNFlood" ? int(1, 3) : 1,
    uniqueDstIps: t.type === "NetworkScan" ? int(8, 60) : 1,
    uniqueDstPorts: t.type === "PortScan" ? int(20, 900) : 1,
    firstSeen: at,
    lastSeen: at,
    flowCount: 0,
    riskSum: 0,
    maxRisk: 0,
    avgRisk: 0,
    eventRisk: 0,
    action: t.action,
    responseGuide: GUIDE[t.type](sub),
    // response_playbook.py 와 같은 형식: 메시지 + 빈 줄 + [설정 파일: a / b]
    actionDetail: `${DETAIL[t.action](src, sub)}\n\n[설정 파일: ${GUIDE[t.type](sub).config_files.map((c) => c.path).join(" / ")}]`,
    state: opts.closed ? "closed" : "open",
    _t: t,
    _target: int(...t.flows),
  };
  events.unshift(e);
  return e;
}

function grow(e, n, now) {
  const t = e._t;
  for (let i = 0; i < n && e.flowCount < e._target; i++) {
    const at = new Date(Math.min(now.getTime(), e.lastSeen.getTime() + int(200, 4000)));
    const risk = +between(...t.risk).toFixed(2);
    const src = e.uniqueSrcIps > 1 ? `${pick(EXTERNAL).split(".").slice(0, 3).join(".")}.${int(2, 254)}` : e.srcIp;
    const dst = e.uniqueDstIps > 1 ? `10.10.0.${int(2, 80)}` : e.destIp;
    const port = e.uniqueDstPorts > 1 ? int(1, 1024) : e.destPort ?? 0;
    const f = makeFlow({ src, dst, port, proto: e.attackSubtype.includes("UDP") || e.attackSubtype.includes("DNS") ? "UDP" : "TCP", at, attackId: e.id, attack: e.attackType, risk });
    if (e.flowCount === 0) e.firstSeen = new Date(f.startTime); // grouper 는 첫 플로우의 시작 시각을 first_seen 으로 기록
    e.flowCount += 1;
    e.riskSum += risk;
    e.maxRisk = Math.max(e.maxRisk, risk);
    e.avgRisk = e.riskSum / e.flowCount;
    e.eventRisk = Math.min(100, 0.7 * e.maxRisk + 0.2 * e.avgRisk + 10 * Math.min(e.flowCount / 100, 1));
    e.lastSeen = at;
  }
}

function normalTraffic(at, n) {
  for (let i = 0; i < n; i++) {
    makeFlow({
      src: pick([...INTERNAL_SRC, "192.168.0.31", "192.168.0.52"]),
      dst: pick([...SERVERS, "8.8.8.8", "142.250.207.14"]),
      port: pick([443, 443, 80, 53, 22, 3306]),
      proto: pick(["TCP", "TCP", "TCP", "UDP"]),
      at: new Date(at.getTime() - int(0, 5000)),
    });
  }
}

// ---------- 과거 7일 데이터 ----------
(function seedHistory() {
  const now = Date.now();
  const starts = [];
  for (let d = 6; d >= 0; d--) {
    const count = d === 0 ? 0 : int(4, 12);
    for (let i = 0; i < count; i++) starts.push(new Date(now - d * 86400000 - int(0, 86000) * 1000));
  }
  // 오늘(최근 24시간): 시간대별로 분포
  for (let h = 23; h >= 1; h--) {
    for (let i = 0; i < int(0, 2); i++) starts.push(new Date(now - h * 3600000 - int(0, 3500) * 1000));
  }
  starts.sort((a, b) => a - b);
  for (const at of starts) {
    const e = newEvent(at, { closed: true });
    grow(e, Math.min(e._target, 40), new Date(at.getTime() + 3600000));
    e.flowCount = Math.max(e.flowCount, e._target); // 과거 공격은 플로우 수만 맞춤 (메모리 절약)
    e.eventRisk = Math.min(100, 0.7 * e.maxRisk + 0.2 * e.avgRisk + 10 * Math.min(e.flowCount / 100, 1));
    normalTraffic(at, 3);
  }
  // 이미 처리된 과거 경보 일부
  for (const e of events.slice(8)) {
    if (rand() < 0.55) triage.set(e.id, { attackId: e.id, status: pick(["RESOLVED", "RESOLVED", "FALSE_POSITIVE", "ACK"]), note: "", assignee: "김관제", updatedAt: iso(new Date(e.lastSeen.getTime() + 600000)) });
  }
  // 오탐 처리된 경보의 플로우는 ai_results.is_false_positive = true (백엔드와 동일)
  for (const [id, t] of triage) {
    if (t.status !== "FALSE_POSITIVE") continue;
    flows.filter((f) => f.attackId === id).forEach((f) => ai.get(f.flowId) && (ai.get(f.flowId).falsePositive = true));
  }
  // 공격 체인 시나리오: 같은 출발지가 단계를 밟아 가는 공격
  const byType = Object.fromEntries(TYPES.map((t) => [t.type, t]));
  const scenario = (src, steps) => {
    for (const [type, minutesAgo, sub, dst, flows] of steps) {
      const e = newEvent(new Date(now - minutesAgo * 60000), { type: byType[type], closed: true });
      e.srcIp = src;
      e.groupKey = `src:${src}`;
      if (sub) {
        e.attackSubtype = sub;
        e.responseGuide = GUIDE[type](sub);
        e.actionDetail = `${DETAIL[e.action](src, sub)}\n\n[설정 파일: ${e.responseGuide.config_files.map((c) => c.path).join(" / ")}]`;
      }
      const svcPort = { SSH: 22, MySQL: 3306, RDP: 3389, FTP: 21, HTTPS: 443, HTTP: 80, DNS: 53, TCP: 80 }[String(sub).split("-")[1]];
      if (svcPort && e.destPort !== null) e.destPort = svcPort;
      if (dst) e.destIp = dst;
      e.uniqueSrcIps = 1;
      e._target = flows;
      grow(e, Math.min(flows, 40), new Date(now - (minutesAgo - 4) * 60000));
      e.flowCount = flows;
    }
  };
  // 외부 공격자: 네트워크 스캔 → 포트 스캔 → SSH 무차별 대입
  scenario("203.0.113.77", [
    ["NetworkScan", 95, "NetworkScan-Sweep", "10.10.0.0", 48],
    ["PortScan", 80, "PortScan-TCP", "10.10.0.21", 230],
    ["BruteForce", 62, "BruteForce-SSH", "10.10.0.21", 85],
  ]);
  // 감염된 내부 단말: 내부 포트 스캔 → DB 무차별 대입 → 외부 C&C 교신
  scenario("192.168.0.52", [
    ["PortScan", 300, "PortScan-TCP", "192.168.0.100", 120],
    ["BruteForce", 285, "BruteForce-MySQL", "192.168.0.100", 40],
    ["C2Beacon", 270, "C2Beacon-HTTPS", "185.220.101.7", 18],
  ]);

  // 지금 진행 중인 공격 2건
  const a = newEvent(new Date(now - 140000), { type: TYPES[1] });
  grow(a, 12, new Date(now));
  const b = newEvent(new Date(now - 60000), { type: TYPES[2] });
  grow(b, 30, new Date(now));
})();

// ---------- 실시간 흉내 ----------
setInterval(() => {
  const now = new Date();
  normalTraffic(now, int(2, 6));
  for (const e of events.filter((x) => x.state === "open")) {
    if (e.flowCount >= e._target || now - e.lastSeen > 120000) e.state = "closed";
    else grow(e, int(1, 6), now);
  }
  if (rand() < 0.18) {
    const e = newEvent(now);
    grow(e, int(1, 4), now);
    console.log(`[mock] 새 공격 #${e.id} ${e.attackSubtype} ${e.srcIp} → ${e.destIp}`);
  }
  if (flows.length > 20000) flows.length = 20000;
}, 3000);

// ---------- 응답 변환 ----------
const toTriage = (id) => triage.get(id) ?? null;
const eventDto = (e) => ({
  id: e.id,
  attackType: e.attackType,
  attackSubtype: e.attackSubtype,
  groupKey: e.groupKey,
  srcIp: e.srcIp,
  destIp: e.destIp,
  destPort: e.destPort,
  uniqueSrcIps: e.uniqueSrcIps,
  uniqueDstIps: e.uniqueDstIps,
  uniqueDstPorts: e.uniqueDstPorts,
  firstSeen: iso(e.firstSeen),
  lastSeen: iso(e.lastSeen),
  flowCount: e.flowCount,
  maxRisk: +e.maxRisk.toFixed(2),
  avgRisk: +e.avgRisk.toFixed(2),
  eventRisk: +e.eventRisk.toFixed(2),
  action: e.action,
  actionDetail: e.actionDetail,
  responseGuide: e.responseGuide,
  state: e.state,
  triage: toTriage(e.id),
});
const aiSummary = (r) =>
  r && { prediction: r.prediction, attackType: r.attackType, attackSubtype: r.attackSubtype, confidence: r.confidence, riskScore: r.riskScore, action: r.action };
const flowItem = (f) => {
  const { bytesToServer, bytesToClient, pktsToServer, pktsToClient, idsSeverity, eventType, idsRuleId, ...rest } = f;
  void bytesToServer, bytesToClient, pktsToServer, pktsToClient, idsSeverity, eventType, idsRuleId;
  return { ...rest, ai: aiSummary(ai.get(f.flowId)) };
};
const page = (list, p, size) => ({
  content: list.slice(p * size, p * size + size),
  totalElements: list.length,
  totalPages: Math.max(1, Math.ceil(list.length / size)),
  number: p,
  size,
});

// ---------- 공격 연관 분석 (백엔드 ChainService 와 같은 규칙) ----------
const STAGE = (t) =>
  ({ NetworkScan: "RECON", PortScan: "RECON", BruteForce: "INTRUSION", C2Beacon: "CONTROL", DDoS: "IMPACT", SYNFlood: "IMPACT" })[t] ?? "ANOMALY";
const ORDER = { ANOMALY: 0, RECON: 1, INTRUSION: 2, CONTROL: 3, IMPACT: 4 };

function buildChains(hours, gapMin, minEvents) {
  const since = Date.now() - hours * 3600000;
  const gap = gapMin * 60000;
  const list = events.filter((e) => e.lastSeen >= since).sort((a, b) => a.firstSeen - b.firstSeen);
  const bySrc = new Map();
  list.forEach((e) => bySrc.set(e.srcIp, [...(bySrc.get(e.srcIp) ?? []), e]));
  const chains = [];
  for (const evs of bySrc.values()) {
    let cur = [];
    let end = null;
    const flush = () => cur.length >= minEvents && chains.push(chainDto(cur));
    for (const e of evs) {
      if (end !== null && e.firstSeen - end > gap) {
        flush();
        cur = [];
        end = null;
      }
      cur.push(e);
      end = Math.max(end ?? 0, e.lastSeen.getTime());
    }
    flush();
  }
  return chains.sort((a, b) => b.chainRisk - a.chainRisk || (b.lastSeen > a.lastSeen ? 1 : -1));
}

function chainDto(group) {
  const stages = [];
  let escalated = false;
  let maxOrder = -1;
  for (const e of group) {
    const st = STAGE(e.attackType);
    if (!stages.includes(st)) stages.push(st);
    if (st !== "ANOMALY") {
      if (maxOrder >= 1 && ORDER[st] > maxOrder) escalated = true;
      maxOrder = Math.max(maxOrder, ORDER[st]);
    }
  }
  const maxRisk = Math.max(...group.map((e) => e.eventRisk));
  const real = stages.filter((x) => x !== "ANOMALY").length;
  const first = group[0].firstSeen;
  const last = new Date(Math.max(...group.map((e) => e.lastSeen.getTime())));
  const targets = [...new Set(group.map((e) => e.destIp))];
  return {
    id: `${group[0].srcIp}@${first.getTime()}`,
    srcIp: group[0].srcIp,
    firstSeen: iso(first),
    lastSeen: iso(last),
    eventCount: group.length,
    flowCount: group.reduce((s, e) => s + e.flowCount, 0),
    targetCount: targets.length,
    targets: targets.slice(0, 5),
    stages,
    highestStage: stages.reduce((h, x) => (ORDER[x] > ORDER[h] ? x : h), "ANOMALY"),
    escalated,
    active: group.some((e) => e.state === "open"),
    maxEventRisk: +maxRisk.toFixed(1),
    chainRisk: +Math.min(100, maxRisk + 8 * Math.max(0, real - 1) + (escalated ? 5 : 0)).toFixed(1),
    events: group.map((e) => ({
      id: e.id,
      attackType: e.attackType,
      attackSubtype: e.attackSubtype,
      stage: STAGE(e.attackType),
      firstSeen: iso(e.firstSeen),
      lastSeen: iso(e.lastSeen),
      destIp: e.destIp,
      destPort: e.destPort,
      flowCount: e.flowCount,
      eventRisk: +e.eventRisk.toFixed(1),
      state: e.state,
    })),
  };
}

// ---------- AI 판정 품질 (백엔드 AiQualityService 와 같은 형식) ----------
function buildQuality(days) {
  const now = new Date();
  const since = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (days - 1));
  const rs = [...ai.values()].filter((r) => new Date(r.analyzedAt) >= since);
  const evs = events.filter((e) => e.firstSeen >= since);
  const order = [...TYPES.map((t) => t.type), "Normal"];
  const types = order.map((type) => {
    const list = rs.filter((r) => r.attackType === type);
    const inc = evs.filter((e) => e.attackType === type);
    const st = (s) => inc.filter((e) => triage.get(e.id)?.status === s).length;
    const resolved = st("RESOLVED");
    const fp = st("FALSE_POSITIVE");
    const ack = st("ACK");
    return {
      type,
      flows: list.length,
      avgConfidence: list.length ? +(list.reduce((s, r) => s + r.confidence, 0) / list.length).toFixed(3) : 0,
      avgRisk: list.length ? +(list.reduce((s, r) => s + r.riskScore, 0) / list.length).toFixed(1) : 0,
      falsePositiveFlows: list.filter((r) => r.falsePositive).length,
      incidents: inc.length,
      resolved,
      falsePositive: fp,
      inProgress: ack,
      untouched: Math.max(0, inc.length - resolved - fp - ack),
    };
  });
  const attacks = rs.filter((r) => r.attackType !== "Normal");
  const hist = (val, w) => {
    const c = Array(10).fill(0);
    attacks.forEach((r) => c[Math.min(9, Math.max(0, Math.floor(val(r) / w)))]++);
    return c.map((count, i) => ({ from: +(i * w).toFixed(2), to: +((i + 1) * w).toFixed(2), count }));
  };
  const reviewed = types.filter((t) => t.type !== "Normal").reduce((s, t) => s + t.resolved + t.falsePositive, 0);
  const fpInc = types.filter((t) => t.type !== "Normal").reduce((s, t) => s + t.falsePositive, 0);
  // 과거 흐름 수 보정 (메모리 절약용 축소분 반영)
  const scale = 37;
  return {
    days,
    analyzedFlows: rs.length * scale,
    attackFlows: attacks.length * scale,
    avgAttackConfidence: attacks.length ? +(attacks.reduce((s, r) => s + r.confidence, 0) / attacks.length).toFixed(3) : 0,
    falsePositiveFlows: rs.filter((r) => r.falsePositive).length,
    reviewedIncidents: reviewed,
    falsePositiveIncidents: fpInc,
    types: types.map((t) => ({ ...t, flows: t.flows * scale })),
    confidenceHistogram: hist((r) => r.confidence, 0.1),
    riskHistogram: hist((r) => r.riskScore, 10),
    models: [{ modelName: "IF+RF+SEQ", modelVersion: "v1_cicids2017", flows: rs.length * scale }],
  };
}

// ---------- 라우팅 ----------

// ---------- IDS 룰 대비 / 탐지 지연 (백엔드 DetectionService 와 같은 규칙) ----------
const LAT_BUCKETS = [["5초 미만", 0, 5], ["5~10초", 5, 10], ["10~30초", 10, 30], ["30~60초", 30, 60], ["1~2분", 60, 120], ["2~5분", 120, 300], ["5분 이상", 300, -1]];
function latStats(values) {
  const valid = [];
  let excluded = 0;
  for (const v of values) (v < -60 || v > 3600 ? excluded++ : valid.push(Math.max(0, Math.floor(v))));
  valid.sort((a, b) => a - b);
  const pct = (p) => (valid.length ? valid[Math.max(0, Math.ceil(p * valid.length) - 1)] : 0);
  return {
    count: valid.length,
    excluded,
    avg: valid.length ? +(valid.reduce((a, b) => a + b, 0) / valid.length).toFixed(1) : 0,
    p50: pct(0.5), p90: pct(0.9), p95: pct(0.95),
    max: valid.length ? valid[valid.length - 1] : 0,
    buckets: LAT_BUCKETS.map(([label, from, to]) => ({ label, fromSec: from, toSec: to, count: valid.filter((v) => v >= from && (to < 0 || v < to)).length })),
  };
}
function buildIdsComparison(days) {
  const since = new Date(Date.now() - days * 86400000);
  const fs = flows.filter((f) => new Date(f.startTime) >= since && ai.has(f.flowId));
  const m = { both: 0, aiOnly: 0, idsOnly: 0, neither: 0 };
  const byType = new Map();
  for (const f of fs) {
    const r = ai.get(f.flowId);
    const aiHit = r.attackType !== "Normal";
    const idsHit = f.idsSeverity != null;
    m[aiHit ? (idsHit ? "both" : "aiOnly") : idsHit ? "idsOnly" : "neither"]++;
    if (aiHit) {
      const t = byType.get(r.attackType) ?? { type: r.attackType, aiFlows: 0, idsAlsoFlows: 0, incidents: 0, idsDetectedIncidents: 0 };
      t.aiFlows++;
      if (idsHit) t.idsAlsoFlows++;
      byType.set(r.attackType, t);
    }
  }
  const idsAttackIds = new Set(flows.filter((f) => f.idsSeverity != null && f.attackId != null).map((f) => f.attackId));
  const evs = events.filter((e) => e.firstSeen >= since);
  for (const e of evs) {
    const t = byType.get(e.attackType) ?? { type: e.attackType, aiFlows: 0, idsAlsoFlows: 0, incidents: 0, idsDetectedIncidents: 0 };
    t.incidents++;
    if (idsAttackIds.has(e.id)) t.idsDetectedIncidents++;
    byType.set(e.attackType, t);
  }
  const idsDetected = evs.filter((e) => idsAttackIds.has(e.id)).length;
  return {
    days,
    flows: m,
    incidents: { total: evs.length, idsDetected, aiOnly: evs.length - idsDetected },
    types: [...byType.values()].sort((a, b) => b.aiFlows - a.aiFlows || b.incidents - a.incidents),
    aiOnlyIncidents: evs.filter((e) => !idsAttackIds.has(e.id)).sort((a, b) => b.eventRisk - a.eventRisk || b.id - a.id).slice(0, 10).map(eventDto),
    idsOnlyFlows: fs.filter((f) => f.idsSeverity != null && ai.get(f.flowId).attackType === "Normal").slice(0, 10).map(flowItem),
  };
}
function buildLatency(days) {
  const since = new Date(Date.now() - days * 86400000);
  const flowLat = [];
  const firstAi = new Map();
  for (const f of flows) {
    const r = ai.get(f.flowId);
    if (!r) continue;
    const at = new Date(r.analyzedAt);
    if (at >= since && r.attackType !== "Normal") flowLat.push((at - new Date(f.endTime)) / 1000);
    if (f.attackId != null) firstAi.set(f.attackId, Math.min(firstAi.get(f.attackId) ?? Infinity, at.getTime()));
  }
  const incLat = events.filter((e) => e.firstSeen >= since && firstAi.has(e.id)).map((e) => (firstAi.get(e.id) - e.firstSeen.getTime()) / 1000);
  return { days, incident: latStats(incLat), flow: latStats(flowLat.slice(0, 20000)) };
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" });
  res.end(body === undefined ? "" : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const q = Object.fromEntries(url.searchParams);
  const p = url.pathname;
  const now = new Date();
  const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  try {
    if (req.method === "OPTIONS") return send(res, 204);

    if (p === "/api/dashboard/summary") {
      const today = events.filter((e) => e.firstSeen >= startOfDay);
      return send(res, 200, {
        totalFlows: flows.length + 1_240_000,
        todayFlows: flows.filter((f) => new Date(f.startTime) >= startOfDay).length * 37,
        todayAttacks: today.length,
        activeAttacks: events.filter((e) => e.state === "open").length,
        realtimeAttack: events.some((e) => e.state === "open" && now - e.lastSeen < 120000),
        avgRisk: today.length ? today.reduce((s, e) => s + e.eventRisk, 0) / today.length : 0,
        maxRisk: today.reduce((m, e) => Math.max(m, e.eventRisk), 0),
      });
    }
    if (p === "/api/dashboard/attack-types") {
      const list = q.period === "today" ? events.filter((e) => e.firstSeen >= startOfDay) : events;
      return send(res, 200, TYPES.map((t) => ({ type: t.type, count: list.filter((e) => e.attackType === t.type).length })));
    }
    if (p === "/api/dashboard/timeline") {
      const out = [];
      for (let i = 6; i >= 0; i--) {
        const d = new Date(startOfDay.getTime() - i * 86400000);
        const next = new Date(d.getTime() + 86400000);
        out.push({ day: `${pad(d.getMonth() + 1)}/${pad(d.getDate())}`, count: events.filter((e) => e.firstSeen >= d && e.firstSeen < next).length });
      }
      return send(res, 200, out);
    }
    if (p === "/api/dashboard/realtime") {
      const since = new Date(now);
      since.setMinutes(0, 0, 0);
      since.setHours(since.getHours() - 23);
      const counts = new Map();
      events.filter((e) => e.firstSeen >= since).forEach((e) => counts.set(e.firstSeen.getHours(), (counts.get(e.firstSeen.getHours()) ?? 0) + 1));
      return send(res, 200, Array.from({ length: 24 }, (_, h) => ({ hour: h, count: counts.get(h) ?? 0 })));
    }

    let m;
    if (p === "/api/incidents") {
      const since = new Date(now.getTime() - Number(q.hours ?? 24) * 3600000);
      const list = events.filter((e) => e.lastSeen >= since).sort((a, b) => b.lastSeen - a.lastSeen);
      return send(res, 200, page(list.map(eventDto), Number(q.page ?? 0), Number(q.size ?? 50)));
    }
    if ((m = p.match(/^\/api\/incidents\/(\d+)$/))) {
      const e = events.find((x) => x.id === Number(m[1]));
      return e ? send(res, 200, eventDto(e)) : send(res, 404, { message: "Incident not found" });
    }
    if ((m = p.match(/^\/api\/incidents\/(\d+)\/flows$/))) {
      const list = flows.filter((f) => f.attackId === Number(m[1]));
      return send(res, 200, page(list.map(flowItem), Number(q.page ?? 0), Number(q.size ?? 20)));
    }
    if ((m = p.match(/^\/api\/incidents\/(\d+)\/triage$/)) && req.method === "PUT") {
      let body = "";
      for await (const chunk of req) body += chunk;
      const data = JSON.parse(body || "{}");
      const rec = { attackId: Number(m[1]), status: data.status ?? "NEW", note: data.note ?? "", assignee: data.assignee ?? "", updatedAt: iso(now) };
      triage.set(rec.attackId, rec);
      const fp = rec.status === "FALSE_POSITIVE";
      flows.filter((f) => f.attackId === rec.attackId).forEach((f) => ai.get(f.flowId) && (ai.get(f.flowId).falsePositive = fp));
      return send(res, 200, rec);
    }

    if (p === "/api/chains") {
      return send(res, 200, buildChains(Number(q.hours ?? 24), Number(q.gap ?? 30), Number(q.minEvents ?? 2)));
    }
    if (p === "/api/ai/ids-comparison") {
      return send(res, 200, buildIdsComparison(Number(q.days ?? 7)));
    }
    if (p === "/api/ai/latency") {
      return send(res, 200, buildLatency(Number(q.days ?? 7)));
    }
    if (p === "/api/ai/quality") {
      return send(res, 200, buildQuality(Number(q.days ?? 7)));
    }
    if (p === "/api/ai/false-positives.csv") {
      const rows = [...ai.values()].filter((r) => r.falsePositive);
      const esc = (v) => (v === null || v === undefined ? "" : `"${String(v).replace(/"/g, '""')}"`);
      const body =
        "\uFEFFflow_id,analyzed_at,model_name,model_version,predicted_type,predicted_subtype,confidence,risk_score,corrected_label,feature_vector\r\n" +
        rows
          .map((r) =>
            [r.flowId, r.analyzedAt, esc(r.modelName), esc(r.modelVersion), esc(r.attackType), esc(r.attackSubtype), r.confidence, r.riskScore, "Normal", esc(JSON.stringify(r.featureVector))].join(",")
          )
          .join("\r\n");
      res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="false_positives.csv"' });
      return res.end(body);
    }
    if (p === "/api/flows") {
      const since = q.hours ? new Date(now.getTime() - Number(q.hours) * 3600000) : null;
      const kw = (q.q ?? "").trim();
      const list = flows.filter((f) => {
        const r = ai.get(f.flowId);
        if (kw && !(f.srcIp.startsWith(kw) || f.destIp.startsWith(kw) || String(f.flowId) === kw)) return false;
        if (q.srcIp && f.srcIp !== q.srcIp) return false;
        if (q.destIp && f.destIp !== q.destIp) return false;
        if (q.port && String(f.destPort) !== q.port) return false;
        if (q.protocol && f.protocol !== q.protocol) return false;
        if (q.attackType && r?.attackType !== q.attackType) return false;
        if (q.verdict === "attack" && (!r || r.attackType === "Normal")) return false;
        if (q.verdict === "normal" && r && r.attackType !== "Normal") return false;
        if (since && new Date(f.startTime) < since) return false;
        return true;
      });
      return send(res, 200, page(list.map(flowItem), Number(q.page ?? 0), Number(q.size ?? 50)));
    }
    if ((m = p.match(/^\/api\/flows\/(\d+)$/))) {
      const f = flows.find((x) => x.flowId === Number(m[1]));
      return f ? send(res, 200, { ...f, aiResult: ai.get(f.flowId) ?? null }) : send(res, 404, { message: "Flow not found" });
    }
    if ((m = p.match(/^\/api\/flows\/(\d+)\/ai-results$/))) {
      const r = ai.get(Number(m[1]));
      return send(res, 200, r ? [r] : []);
    }
    return send(res, 404, { message: `No mock for ${p}` });
  } catch (err) {
    console.error(err);
    return send(res, 500, { message: String(err) });
  }
});

server.listen(PORT, () => {
  console.log(`[mock] 목업 API 실행 중: http://localhost:${PORT}  (공격 ${events.length}건, 플로우 ${flows.length}건)`);
});
