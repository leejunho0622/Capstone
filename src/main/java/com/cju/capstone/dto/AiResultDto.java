package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;

import java.time.LocalDateTime;

public record AiResultDto(
        Long id,
        Long flowId,
        String modelName,
        String prediction,
        String attackType,
        double confidence,
        double riskScore,
        String action,
        String actionDetail,
        LocalDateTime analyzedAt
) {
    public static AiResultDto from(AiResult a) {
        return new AiResultDto(
                a.getId(),
                a.getFlow().getFlowId(),
                a.getModelName(),
                a.getPrediction(),
                a.getAttackType(),
                a.getConfidence(),
                a.getRiskScore(),
                a.getAction(),
                a.getActionDetail(),
                a.getAnalyzedAt()
        );
    }
}