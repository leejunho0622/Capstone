package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;

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

        int synCount,
        int ackCount,
        int finCount,
        int rstCount,
        int pshCount,
        int urgCount,

        AiResultDto aiResult

) {

    public static FlowDetailDto of(
            Flow flow,
            FlowFlags flags,
            AiResult ai
    ) {

        return new FlowDetailDto(

                flow.getFlowId(),
                flow.getSrcIp(),
                flow.getDestIp(),

                flow.getSrcPort(),
                flow.getDestPort(),

                flow.getProtocol(),

                flow.getStartTime(),
                flow.getEndTime(),

                flags != null
                        ? flags.getSynCount()
                        : 0,

                flags != null
                        ? flags.getAckCount()
                        : 0,

                flags != null
                        ? flags.getFinCount()
                        : 0,

                flags != null
                        ? flags.getRstCount()
                        : 0,

                flags != null
                        ? flags.getPshCount()
                        : 0,

                flags != null
                        ? flags.getUrgCount()
                        : 0,

                ai != null
                        ? AiResultDto.from(ai)
                        : null

        );
    }
}