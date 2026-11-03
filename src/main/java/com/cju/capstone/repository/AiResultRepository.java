package com.cju.capstone.repository;

import com.cju.capstone.domain.AiResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}
