package com.cju.capstone.dto;

import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;

import java.time.LocalDateTime;

public record FlowDto(
        Long flowId,
        String srcIp,
        String destIp,
        int srcPort,
        int destPort,
        String protocol,
        LocalDateTime startTime,
        LocalDateTime endTime,

        // 🔥 flags 추가
        int synCount,
        int ackCount,
        int finCount,
        int rstCount,
        int pshCount,
        int urgCount
) {
    public static FlowDto from(Flow f, FlowFlags flags) {
        return new FlowDto(
                f.getFlowId(),
                f.getSrcIp(),
                f.getDestIp(),
                f.getSrcPort(),
                f.getDestPort(),
                f.getProtocol(),
                f.getStartTime(),
                f.getEndTime(),

                flags != null ? flags.getSynCount() : 0,
                flags != null ? flags.getAckCount() : 0,
                flags != null ? flags.getFinCount() : 0,
                flags != null ? flags.getRstCount() : 0,
                flags != null ? flags.getPshCount() : 0,
                flags != null ? flags.getUrgCount() : 0
        );
    }
}