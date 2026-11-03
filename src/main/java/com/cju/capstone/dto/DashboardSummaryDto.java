package com.cju.capstone.dto;

/** GET /api/dashboard/summary */
public record DashboardSummaryDto(
        long totalFlows,       // 누적 수집 플로우
        long todayFlows,       // 오늘 수집 플로우
        long todayAttacks,     // 오늘 시작된 공격(attack_events) 수
        long activeAttacks,    // 진행 중(open) 공격 수
        boolean realtimeAttack,// 최근 2분 안에 활동한 진행 중 공격 존재 여부
        double avgRisk,        // 오늘 공격의 종합 위험도 평균
        double maxRisk         // 오늘 공격의 종합 위험도 최대
) {
}
