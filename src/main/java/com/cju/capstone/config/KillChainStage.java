package com.cju.capstone.config;

/**
 * 공격 체인 단계 (MITRE ATT&CK 전술 순서를 단순화)
 * 정찰 → 침투 시도 → 장악(C2) → 영향(서비스 마비)
 * 같은 출발지의 공격이 앞 단계에서 뒤 단계로 넘어가면 '공격 진행(escalation)'으로 본다.
 */
public enum KillChainStage {
    ANOMALY(0, "미분류 이상"),     // UnknownAnomaly 등 단계를 특정할 수 없는 경우
    RECON(1, "정찰"),             // NetworkScan, PortScan  (TA0043 Reconnaissance / TA0007 Discovery)
    INTRUSION(2, "침투 시도"),     // BruteForce            (TA0006 Credential Access)
    CONTROL(3, "장악·C2"),         // C2Beacon              (TA0011 Command and Control)
    IMPACT(4, "서비스 공격");       // DDoS, SYNFlood        (TA0040 Impact)

    private final int order;
    private final String label;

    KillChainStage(int order, String label) {
        this.order = order;
        this.label = label;
    }

    public int order() {
        return order;
    }

    public String label() {
        return label;
    }

    /** attack_type (또는 "BruteForce-SSH" 같은 세부 유형) → 단계 */
    public static KillChainStage of(String attackType) {
        String t = attackType == null ? "" : attackType.split("-")[0].trim();
        return switch (t) {
            case "NetworkScan", "PortScan" -> RECON;
            case "BruteForce" -> INTRUSION;
            case "C2Beacon" -> CONTROL;
            case "DDoS", "SYNFlood" -> IMPACT;
            default -> ANOMALY;
        };
    }
}
