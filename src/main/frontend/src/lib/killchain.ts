/* =========================================================
   공격 체인 단계 (백엔드 config/KillChainStage 와 동일)
   MITRE ATT&CK 전술(Tactic) 이름 기준
   정찰 → 자격 증명 접근 → 명령 및 제어(C2) → 영향(서비스 거부)
   ========================================================= */

export type StageKey = "RECON" | "INTRUSION" | "CONTROL" | "IMPACT" | "ANOMALY";

/** label: 전체 이름(표·상세), short: 좁은 칸용 이름, note: 대표 기법 (단계 상자 3줄 구조를 맞추기 위해 모두 지정) */
export const STAGES: Array<{ key: StageKey; order: number; label: string; short: string; note: string; tactic: string; examples: string }> = [
  { key: "RECON", order: 1, label: "정찰", short: "정찰", note: "스캔", tactic: "TA0043 Reconnaissance · TA0007 Discovery", examples: "Network Scan, Port Scan" },
  { key: "INTRUSION", order: 2, label: "자격 증명 접근", short: "자격 증명 접근", note: "무차별 대입", tactic: "TA0006 Credential Access", examples: "Brute Force" },
  { key: "CONTROL", order: 3, label: "명령 및 제어 (C2)", short: "명령 및 제어", note: "C2 통신", tactic: "TA0011 Command and Control", examples: "C2 Beacon" },
  { key: "IMPACT", order: 4, label: "영향 (서비스 거부)", short: "영향", note: "서비스 거부", tactic: "TA0040 Impact", examples: "DDoS, SYN Flood" },
];

export const STAGE_LABEL: Record<StageKey, string> = {
  RECON: "정찰",
  INTRUSION: "자격 증명 접근",
  CONTROL: "명령 및 제어 (C2)",
  IMPACT: "영향 (서비스 거부)",
  ANOMALY: "단계 미분류",
};

export function stageOf(attackType: string | null | undefined): StageKey {
  const t = String(attackType ?? "").split("-")[0];
  if (t === "NetworkScan" || t === "PortScan") return "RECON";
  if (t === "BruteForce") return "INTRUSION";
  if (t === "C2Beacon") return "CONTROL";
  if (t === "DDoS" || t === "SYNFlood") return "IMPACT";
  return "ANOMALY";
}
