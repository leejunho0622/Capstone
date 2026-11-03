package com.cju.capstone.dto;

import java.util.List;

/**
 * AI 판정 품질 (GET /api/ai/quality)
 * - 모델 쪽 지표: 유형별 분석 건수·평균 신뢰도·평균 위험도, 신뢰도/위험도 분포
 * - 사람 쪽 지표: 관제요원이 처리한 경보 중 '조치 완료(정탐)' vs '오탐' 비율
 */
public record AiQualityDto(
        int days,
        long analyzedFlows,          // 기간 내 분석된 플로우 수
        long attackFlows,            // 그중 공격 판정
        double avgAttackConfidence,  // 공격 판정 평균 신뢰도 (0~1)
        long falsePositiveFlows,     // 오탐 표시된 플로우 수
        long reviewedIncidents,      // 관제요원이 판정(조치 완료/오탐)한 경보 수
        long falsePositiveIncidents, // 그중 오탐
        List<TypeQuality> types,
        List<Bucket> confidenceHistogram,
        List<Bucket> riskHistogram,
        List<ModelUsage> models
) {
    public record TypeQuality(
            String type,
            long flows,
            double avgConfidence,
            double avgRisk,
            long falsePositiveFlows,
            long incidents,          // 공격(경보) 수
            long resolved,           // 조치 완료 (정탐 확정)
            long falsePositive,      // 오탐 확정
            long inProgress,         // 확인 중
            long untouched           // 아직 신규
    ) {
    }

    /** from 이상 to 미만 구간의 건수 */
    public record Bucket(double from, double to, long count) {
    }

    public record ModelUsage(String modelName, String modelVersion, long flows) {
    }
}
