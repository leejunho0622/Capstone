package com.cju.capstone.dto;

import java.util.List;

/** 탐지 성능: IDS 룰 대비 AI, 탐지 지연 */
public final class DetectionDto {

    private DetectionDto() {
    }

    /** GET /api/ai/ids-comparison */
    public record IdsComparison(
            int days,
            FlowMatrix flows,
            IncidentSummary incidents,
            List<TypeRow> types,
            List<IncidentDto> aiOnlyIncidents,  // IDS 룰이 하나도 못 잡은 공격 (위험도 순)
            List<FlowDto> idsOnlyFlows          // 룰은 잡았는데 AI 는 정상으로 본 플로우
    ) {
    }

    /** 플로우 단위 2×2 */
    public record FlowMatrix(long both, long aiOnly, long idsOnly, long neither) {
    }

    /** 공격 단위: 전체 공격 중 IDS 가 일부라도 잡은 공격 */
    public record IncidentSummary(long total, long idsDetected, long aiOnly) {
    }

    public record TypeRow(
            String type,
            long aiFlows,          // AI 가 이 유형으로 판정한 플로우
            long idsAlsoFlows,     // 그중 IDS 도 탐지
            long incidents,        // 이 유형의 공격 수
            long idsDetectedIncidents
    ) {
    }

    /** GET /api/ai/latency */
    public record Latency(
            int days,
            LatencyStats incident,  // 공격 시작 → 첫 AI 판정 (MTTD)
            LatencyStats flow       // 연결 종료 → AI 분석
    ) {
    }

    public record LatencyStats(
            long count,             // 계산에 쓴 건수
            long excluded,          // 제외한 건수 (음수·1시간 초과: 합성 데이터 또는 시간대 불일치)
            double avg,
            double p50,
            double p90,
            double p95,
            double max,
            List<Bucket> buckets
    ) {
    }

    public record Bucket(String label, long fromSec, long toSec, long count) {
    }
}
