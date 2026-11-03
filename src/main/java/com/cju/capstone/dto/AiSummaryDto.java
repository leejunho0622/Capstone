package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;

/** 목록용 AI 판정 요약 (무거운 JSON 컬럼 제외) */
public record AiSummaryDto(
        String prediction,
        String attackType,
        String attackSubtype,
        Double confidence,
        Double riskScore,
        String action
) {
    public static AiSummaryDto from(AiResult a) {
        if (a == null) {
            return null;
        }
        return new AiSummaryDto(a.getPrediction(), a.getAttackType(), a.getAttackSubtype(),
                a.getConfidence(), a.getRiskScore(), a.getAction());
    }
}
