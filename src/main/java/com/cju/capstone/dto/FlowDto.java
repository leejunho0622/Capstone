package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;

import java.time.LocalDateTime;

/** 트래픽 목록 항목 = 플로우 + TCP 플래그 + 최신 AI 판정 요약 */
public record FlowDto(
        Long flowId,
        String srcIp,
        String destIp,
        Integer srcPort,
        Integer destPort,
        String protocol,
        LocalDateTime startTime,
        LocalDateTime endTime,
        Long attackId,
        int synCount,
        int ackCount,
        int finCount,
        int rstCount,
        int pshCount,
        int urgCount,
        AiSummaryDto ai
) {
    public static FlowDto of(Flow f, FlowFlags flags, AiResult ai) {
        return new FlowDto(
                f.getFlowId(),
                f.getSrcIp(),
                f.getDestIp(),
                f.getSrcPort(),
                f.getDestPort(),
                f.getProtocol(),
                f.getStartTime(),
                f.getEndTime(),
                f.getAttackId(),
                flags != null ? flags.getSynCount() : 0,
                flags != null ? flags.getAckCount() : 0,
                flags != null ? flags.getFinCount() : 0,
                flags != null ? flags.getRstCount() : 0,
                flags != null ? flags.getPshCount() : 0,
                flags != null ? flags.getUrgCount() : 0,
                AiSummaryDto.from(ai)
        );
    }
}
