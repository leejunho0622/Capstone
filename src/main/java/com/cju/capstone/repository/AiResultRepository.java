package com.cju.capstone.repository;

import com.cju.capstone.domain.AiResult;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface AiResultRepository extends JpaRepository<AiResult, Long> {

    /** 플로우의 최신 분석 결과 (이전 findTopByFlow_FlowId 는 정렬이 없어 임의의 결과가 나왔음) */
    Optional<AiResult> findFirstByFlowIdOrderByAnalyzedAtDescIdDesc(Long flowId);

    /** 플로우의 분석 이력 (최신순) */
    List<AiResult> findAllByFlowIdOrderByAnalyzedAtDescIdDesc(Long flowId);

    /** 목록 화면용 일괄 조회 - 서비스에서 플로우별 최신 1건만 고름 */
    List<AiResult> findAllByFlowIdIn(Collection<Long> flowIds);

    /**
     * 경보를 오탐으로 처리하면 그 공격에 묶인 플로우의 분석 결과에 오탐 표시
     * (ai_results.is_false_positive 는 원래 '관리자 오탐 표시 → 재학습' 용도로 만들어진 컬럼)
     */
    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE AiResult a SET a.falsePositive = :value
            WHERE a.flowId IN (SELECT f.flowId FROM Flow f WHERE f.attackId = :attackId)
            """)
    int markFalsePositiveByAttackId(@Param("attackId") Long attackId, @Param("value") boolean value);

    // ---------------- AI 판정 품질 (/api/ai/quality) ----------------

    /** [유형, 분석 건수, 평균 신뢰도, 평균 위험도, 오탐 표시 건수] */
    @Query("""
            SELECT a.attackType, COUNT(a), AVG(a.confidence), AVG(a.riskScore),
                   SUM(CASE WHEN a.falsePositive = true THEN 1 ELSE 0 END)
            FROM AiResult a
            WHERE a.analyzedAt >= :since
            GROUP BY a.attackType
            """)
    List<Object[]> qualityByType(@Param("since") LocalDateTime since);

    /** 공격 판정의 신뢰도 분포 (0.1 단위 10구간) [구간, 건수] */
    @Query(value = """
            SELECT LEAST(FLOOR(confidence * 10), 9) AS bucket, COUNT(*)
            FROM ai_results
            WHERE analyzed_at >= :since AND attack_type <> 'Normal' AND confidence IS NOT NULL
            GROUP BY bucket
            """, nativeQuery = true)
    List<Object[]> confidenceHistogram(@Param("since") LocalDateTime since);

    /** 공격 판정의 위험도 분포 (10점 단위 10구간) [구간, 건수] */
    @Query(value = """
            SELECT LEAST(FLOOR(risk_score / 10), 9) AS bucket, COUNT(*)
            FROM ai_results
            WHERE analyzed_at >= :since AND attack_type <> 'Normal' AND risk_score IS NOT NULL
            GROUP BY bucket
            """, nativeQuery = true)
    List<Object[]> riskHistogram(@Param("since") LocalDateTime since);

    /** 사용 중인 모델 [모델명, 버전, 건수] */
    @Query("""
            SELECT a.modelName, a.modelVersion, COUNT(a)
            FROM AiResult a
            WHERE a.analyzedAt >= :since
            GROUP BY a.modelName, a.modelVersion
            """)
    List<Object[]> modelUsage(@Param("since") LocalDateTime since);

    /** 재학습용 오탐 데이터 (feature_vector 포함) */
    List<AiResult> findByFalsePositiveTrueAndAnalyzedAtGreaterThanEqualOrderByAnalyzedAtDesc(
            LocalDateTime since, Pageable pageable);
}
