package com.cju.capstone.dto;

import com.cju.capstone.domain.AiResult;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.LocalDateTime;

/** AI 분석 결과 전체 (상세 화면용) */
public record AiResultDto(
        Long id,
        Long flowId,
        String modelName,
        String modelVersion,
        String prediction,
        String attackType,
        String attackSubtype,
        Double confidence,
        Double riskScore,
        String action,
        String actionDetail,
        JsonNode responseGuide,   // 대응 가이드 (설정 파일 경로·점검 명령)
        JsonNode riskBreakdown,   // 위험도 산출 근거 (components / multipliers / inputs)
        boolean falsePositive,
        LocalDateTime analyzedAt
) {
    public static AiResultDto from(AiResult a) {
        if (a == null) {
            return null;
        }
        return new AiResultDto(
                a.getId(),
                a.getFlowId(),
                a.getModelName(),
                a.getModelVersion(),
                a.getPrediction(),
                a.getAttackType(),
                a.getAttackSubtype(),
                a.getConfidence(),
                a.getRiskScore(),
                a.getAction(),
                a.getActionDetail(),
                JsonColumns.parse(a.getResponseGuide()),
                JsonColumns.parse(a.getRiskBreakdown()),
                Boolean.TRUE.equals(a.getFalsePositive()),
                a.getAnalyzedAt()
        );
    }
}
