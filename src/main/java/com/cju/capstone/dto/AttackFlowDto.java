package com.cju.capstone.dto;

public record AttackFlowDto(

        FlowDto flow,
        AiResultDto aiResult

) {
    public static AttackFlowDto of(
            FlowDto flow,
            AiResultDto aiResult
    ) {
        return new AttackFlowDto(flow, aiResult);
    }
}