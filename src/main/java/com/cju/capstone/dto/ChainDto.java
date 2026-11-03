package com.cju.capstone.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 공격 체인 = 같은 출발지에서 시간 간격 안에 이어진 공격(attack_events) 묶음
 */
public record ChainDto(
        String id,                 // "출발지IP@최초탐지시각" (화면 식별용)
        String srcIp,
        LocalDateTime firstSeen,
        LocalDateTime lastSeen,
        int eventCount,            // 묶인 공격 수
        long flowCount,            // 묶인 플로우 합계
        int targetCount,           // 고유 목적지 수
        List<String> targets,      // 대표 목적지 (최대 5개)
        List<String> stages,       // 거쳐 간 단계 (순서대로, 예: RECON, INTRUSION)
        String highestStage,       // 가장 많이 진행된 단계
        boolean escalated,         // 앞 단계 → 뒤 단계로 진행했는가
        boolean active,            // 진행 중(open) 공격이 포함돼 있는가
        double maxEventRisk,       // 묶인 공격 중 최대 위험도
        double chainRisk,          // 체인 위험도 (단계 진행 가중)
        List<ChainEventDto> events // 시간순
) {
    public record ChainEventDto(
            Long id,
            String attackType,
            String attackSubtype,
            String stage,
            LocalDateTime firstSeen,
            LocalDateTime lastSeen,
            String destIp,
            Integer destPort,
            int flowCount,
            double eventRisk,
            String state
    ) {
    }
}
