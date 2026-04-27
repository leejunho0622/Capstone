package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;

import java.time.LocalDateTime;

public record FlowDetailDto(
        Long flowId,
        String srcIp,
        String destIp,
        int srcPort,
        int destPort,
        String protocol,
        LocalDateTime startTime,
        LocalDateTime endTime,
        AiResultDto aiResult
) {
    public static FlowDetailDto of(Flow f, AiResult a) {

        AiResultDto aiDto = (a != null) ? AiResultDto.from(a) : null;

        return new FlowDetailDto(
                f.getFlowId(),
                f.getSrcIp(),
                f.getDestIp(),
                f.getSrcPort(),
                f.getDestPort(),
                f.getProtocol(),
                f.getStartTime(),
                f.getEndTime(),
                aiDto
        );
    }
}