package com.cju.capstone.dto;

import com.cju.capstone.domain.AttackEvent;
import com.cju.capstone.domain.IncidentTriage;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.LocalDateTime;

/** 경보(공격 1건) = attack_events 1행 + 처리 상태 */
public record IncidentDto(
        Long id,
        String attackType,
        String attackSubtype,
        String groupKey,
        String srcIp,
        String destIp,
        Integer destPort,
        int uniqueSrcIps,
        int uniqueDstIps,
        int uniqueDstPorts,
        LocalDateTime firstSeen,
        LocalDateTime lastSeen,
        int flowCount,
        double maxRisk,
        double avgRisk,
        double eventRisk,
        String action,
        String actionDetail,
        JsonNode responseGuide,
        String state,          // open / closed (파이프라인 기준 진행 여부)
        TriageDto triage       // 관제요원 처리 상태 (없으면 null = 신규)
) {
    public static IncidentDto of(AttackEvent e, IncidentTriage triage) {
        return new IncidentDto(
                e.getId(),
                e.getAttackType(),
                e.getAttackSubtype(),
                e.getGroupKey(),
                e.getSrcIp(),
                e.getDestIp(),
                e.getDestPort(),
                orOne(e.getUniqueSrcIps()),
                orOne(e.getUniqueDstIps()),
                orOne(e.getUniqueDstPorts()),
                e.getFirstSeen(),
                e.getLastSeen(),
                e.getFlowCount() != null ? e.getFlowCount() : 0,
                orZero(e.getMaxRisk()),
                orZero(e.getAvgRisk()),
                orZero(e.getEventRisk()),
                e.getAction(),
                e.getActionDetail(),
                JsonColumns.parse(e.getResponseGuide()),
                e.getState(),
                TriageDto.from(triage)
        );
    }

    private static int orOne(Integer v) {
        return v != null ? v : 1;
    }

    private static double orZero(Double v) {
        return v != null ? v : 0.0;
    }
}
