package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;

import java.time.LocalDateTime;

/** 플로우 상세 = 연결 정보 + 송수신량 + Suricata 탐지 정보 + 플래그 + 최신 AI 결과 */
public record FlowDetailDto(
        Long flowId,
        String srcIp,
        String destIp,
        Integer srcPort,
        Integer destPort,
        String protocol,
        LocalDateTime startTime,
        LocalDateTime endTime,
        Long attackId,
        Long bytesToServer,
        Long bytesToClient,
        Integer pktsToServer,
        Integer pktsToClient,
        Integer idsSeverity,
        String eventType,
        String idsRuleId,
        int synCount,
        int ackCount,
        int finCount,
        int rstCount,
        int pshCount,
        int urgCount,
        AiResultDto aiResult
) {
    public static FlowDetailDto of(Flow f, FlowFlags flags, AiResult ai) {
        return new FlowDetailDto(
                f.getFlowId(),
                f.getSrcIp(),
                f.getDestIp(),
                f.getSrcPort(),
                f.getDestPort(),
                f.getProtocol(),
                f.getStartTime(),
                f.getEndTime(),
                f.getAttackId(),
                f.getBytesToServer(),
                f.getBytesToClient(),
                f.getPktsToServer(),
                f.getPktsToClient(),
                f.getSeverity(),
                f.getEventType(),
                f.getIdsRuleId(),
                flags != null ? flags.getSynCount() : 0,
                flags != null ? flags.getAckCount() : 0,
                flags != null ? flags.getFinCount() : 0,
                flags != null ? flags.getRstCount() : 0,
                flags != null ? flags.getPshCount() : 0,
                flags != null ? flags.getUrgCount() : 0,
                AiResultDto.from(ai)
        );
    }
}
