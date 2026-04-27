package com.cju.capstone.dto;

import com.cju.capstone.domain.Flow;

import java.time.LocalDateTime;

public record FlowDto(
        Long flowId,
        String srcIp,
        String destIp,
        int srcPort,
        int destPort,
        String protocol,
        LocalDateTime startTime,
        LocalDateTime endTime
) {
    public static FlowDto from(Flow f) {
        return new FlowDto(
                f.getFlowId(),
                f.getSrcIp(),
                f.getDestIp(),
                f.getSrcPort(),
                f.getDestPort(),
                f.getProtocol(),
                f.getStartTime(),
                f.getEndTime()
        );
    }
}