/* =========================================================
   공격 유형 정의
   - AI 파이프라인(inference.py) 판정 유형 7종 + Normal
     (BruteForce, PortScan, NetworkScan, DDoS, SYNFlood, C2Beacon, UnknownAnomaly)
   - 세부 유형(attack_subtype)은 "BruteForce-SSH" 처럼 상위유형-서비스 형식
   - 색상: dataviz 검증 범주 팔레트를 '고정 순서'로 배정
     (필터로 개수가 바뀌어도 같은 유형은 같은 색 유지)
   ========================================================= */

export type AttackKey =
  | "BruteForce"
  | "PortScan"
  | "NetworkScan"
  | "DDoS"
  | "SYNFlood"
  | "C2Beacon"
  | "UnknownAnomaly"
  | "Normal"
  | "Unknown";

export interface AttackTypeInfo {
  key: AttackKey;
  label: string;
  labelKo: string;
  color: string;
  mitre: { id: string; name: string; tactic: string; url: string } | null;
  description: string;
  playbook: string[];
}

const mitreUrl = (id: string) =>
  `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

export const ATTACK_TYPES: Record<AttackKey, AttackTypeInfo> = {
  BruteForce: {
    key: "BruteForce",
    label: "Brute Force",
    labelKo: "무차별 대입",
    color: "var(--c-cat-1)",
    mitre: {
      id: "T1110",
      name: "Brute Force",
      tactic: "Credential Access",
      url: mitreUrl("T1110"),
    },
    description:
      "동일 출발지에서 인증 서비스(SSH, RDP, 웹 로그인 등)로 짧은 간격의 반복 접속이 발생했습니다. 비밀번호 대입 공격 가능성이 높습니다.",
    playbook: [
      "출발지 IP 임시 차단 (방화벽/fail2ban)",
      "대상 계정의 로그인 실패 이력 및 성공 여부 확인",
      "로그인 실패 횟수 제한 · MFA 적용 여부 점검",
    ],
  },
  PortScan: {
    key: "PortScan",
    label: "Port Scan",
    labelKo: "포트 스캔",
    color: "var(--c-cat-2)",
    mitre: {
      id: "T1046",
      name: "Network Service Discovery",
      tactic: "Discovery",
      url: mitreUrl("T1046"),
    },
    description:
      "단일 출발지가 짧은 시간에 여러 포트로 연결을 시도했습니다(SYN 후 RST 패턴). 공격 전 열린 서비스를 탐색하는 정찰 단계입니다.",
    playbook: [
      "출발지 IP 를 관찰 목록에 등록",
      "노출된 불필요 포트 차단 여부 점검",
      "동일 출발지의 후속 공격(Brute Force 등) 모니터링",
    ],
  },
  NetworkScan: {
    key: "NetworkScan",
    label: "Network Scan",
    labelKo: "네트워크 스캔",
    color: "var(--c-cat-3)",
    mitre: {
      id: "T1595.001",
      name: "Active Scanning: Scanning IP Blocks",
      tactic: "Reconnaissance",
      url: mitreUrl("T1595.001"),
    },
    description:
      "단일 출발지가 여러 호스트로 접근을 시도했습니다. 내부망의 활성 호스트를 찾는 정찰 활동입니다.",
    playbook: [
      "출발지 IP 의 내부/외부 여부 확인",
      "내부 출발지라면 해당 단말 악성코드 감염 여부 점검",
      "세그먼트 간 접근 통제(ACL) 확인",
    ],
  },
  DDoS: {
    key: "DDoS",
    label: "DDoS",
    labelKo: "분산 서비스 거부",
    color: "var(--c-cat-4)",
    mitre: {
      id: "T1498",
      name: "Network Denial of Service",
      tactic: "Impact",
      url: mitreUrl("T1498"),
    },
    description:
      "다수 출발지에서 특정 대상으로 트래픽이 집중되었습니다. 서비스 가용성 저하가 우려됩니다.",
    playbook: [
      "대상 서비스 응답 상태 및 대역폭 확인",
      "Rate limiting · 상위 회선 차단 요청 검토",
      "공격 출발지 대역 집계 후 차단 정책 적용",
    ],
  },
  SYNFlood: {
    key: "SYNFlood",
    label: "SYN Flood",
    labelKo: "SYN 플러딩",
    color: "var(--c-cat-5)",
    mitre: {
      id: "T1498.001",
      name: "Network DoS: Direct Network Flood",
      tactic: "Impact",
      url: mitreUrl("T1498.001"),
    },
    description:
      "응답(ACK) 없이 SYN 패킷이 대량으로 유입되어 연결 대기열을 고갈시키는 패턴입니다.",
    playbook: [
      "SYN Cookie 활성화 여부 확인",
      "출발지별 SYN 임계치 기반 차단",
      "대상 서버의 half-open 연결 수 모니터링",
    ],
  },
  C2Beacon: {
    key: "C2Beacon",
    label: "C2 Beacon",
    labelKo: "C&C 비콘",
    color: "var(--c-cat-6)",
    mitre: {
      id: "T1071",
      name: "Application Layer Protocol",
      tactic: "Command and Control",
      url: mitreUrl("T1071"),
    },
    description:
      "내부 호스트가 외부 IP 로 일정한 주기·크기의 통신을 반복합니다. 이미 침투에 성공한 악성코드가 명령 서버(C&C)와 교신하는 패턴입니다.",
    playbook: [
      "해당 내부 호스트를 네트워크에서 즉시 격리",
      "외부 목적지 IP/도메인 아웃바운드 차단",
      "호스트 악성코드 정밀 검사 및 침투 경로 조사",
    ],
  },
  UnknownAnomaly: {
    key: "UnknownAnomaly",
    label: "Unknown Anomaly",
    labelKo: "미지 이상징후",
    color: "var(--c-cat-7)",
    mitre: null,
    description:
      "분류 모델(RF)은 정상으로 봤지만 이상 탐지 모델(IsolationForest)의 이상도가 임계값(0.65)을 넘었습니다. 학습되지 않은 새로운 공격일 수 있습니다.",
    playbook: [
      "원본 플로우와 같은 출발지의 전후 기록 확인",
      "Suricata 탐지 규칙/임계값 점검",
      "반복되면 보안팀 에스컬레이션 후 학습 데이터로 수집",
    ],
  },
  Normal: {
    key: "Normal",
    label: "Normal",
    labelKo: "정상",
    color: "var(--c-cat-other)",
    mitre: null,
    description: "AI 모델이 정상 트래픽으로 판정했습니다.",
    playbook: [],
  },
  Unknown: {
    key: "Unknown",
    label: "Unknown",
    labelKo: "미분류",
    color: "var(--c-cat-other)",
    mitre: null,
    description: "분류되지 않은 이상 트래픽입니다. 원본 플로우를 직접 확인하세요.",
    playbook: ["원본 플로우와 동일 출발지의 다른 기록 확인"],
  },
};

/** 차트·필터에서 쓰는 고정 순서 (Normal 제외) */
export const ATTACK_ORDER: AttackKey[] = [
  "BruteForce",
  "PortScan",
  "NetworkScan",
  "DDoS",
  "SYNFlood",
  "C2Beacon",
  "UnknownAnomaly",
];

export function normalizeAttackKey(raw: string | null | undefined): AttackKey {
  // "BruteForce-SSH" 같은 세부 유형도 상위 유형으로 인식
  const v = String(raw ?? "")
    .split("-")[0]
    .toLowerCase()
    .replace(/[\s_]/g, "");
  if (!v) return "Unknown";
  if (v.includes("brute")) return "BruteForce";
  if (v.includes("portscan") || v === "port") return "PortScan";
  if (v.includes("networkscan") || v.includes("netscan")) return "NetworkScan";
  if (v.includes("synflood") || v === "syn") return "SYNFlood";
  if (v.includes("c2") || v.includes("beacon")) return "C2Beacon";
  if (v.includes("anomaly")) return "UnknownAnomaly";
  if (v.includes("ddos") || v.includes("dos")) return "DDoS";
  if (["normal", "benign", "정상", "안전"].some((n) => v.includes(n)))
    return "Normal";
  return "Unknown";
}

export function attackInfo(raw: string | null | undefined): AttackTypeInfo {
  return ATTACK_TYPES[normalizeAttackKey(raw)];
}
