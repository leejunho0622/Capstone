package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * ai_results : 플로우 1건에 대한 AI 분석 결과 (inference.py 가 적재)
 * JSON 컬럼(response_guide, risk_breakdown)은 문자열로 읽어 DTO 에서 JSON 객체로 변환한다.
 */
@Entity
@Table(name = "ai_results")
@Getter
public class AiResult {

    @Id
    private Long id;

    @Column(name = "flow_id", nullable = false)
    private Long flowId;

    @Column(name = "model_name")
    private String modelName;

    @Column(name = "model_version")
    private String modelVersion;

    private String prediction;

    @Column(name = "attack_type")
    private String attackType;

    @Column(name = "attack_subtype")
    private String attackSubtype;

    private Double confidence;

    @Column(name = "risk_score")
    private Double riskScore;

    private String action;

    @Column(name = "action_detail", columnDefinition = "TEXT")
    private String actionDetail;

    @Column(name = "response_guide", columnDefinition = "JSON")
    private String responseGuide;

    @Column(name = "risk_breakdown", columnDefinition = "JSON")
    private String riskBreakdown;

    /** 모델 입력 14개 특징값 (재학습·디버깅용) */
    @Column(name = "feature_vector", columnDefinition = "JSON")
    private String featureVector;

    /** 관리자가 오탐으로 표시한 결과 (재학습 데이터로 활용) */
    @Column(name = "is_false_positive")
    private Boolean falsePositive;

    @Column(name = "analyzed_at")
    private LocalDateTime analyzedAt;
}
