package com.cju.capstone.repository;

import com.cju.capstone.domain.Flow;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface FlowRepository extends JpaRepository<Flow, Long> {

    Optional<Flow> findByFlowId(Long flowId);

    List<Flow> findAllByFlowIdIn(Collection<Long> flowIds);

    /** 한 공격(attack_events)에 묶인 플로우 - v_attack_flows 뷰와 같은 결과 */
    Page<Flow> findByAttackId(Long attackId, Pageable pageable);

    long countByStartTimeGreaterThanEqual(LocalDateTime since);

    /**
     * 트래픽 검색 (모든 조건은 선택 사항)
     * - 문자열 조건은 '' 이면 무시, 숫자 조건은 -1 이면 무시 (Hibernate 6 의 null 파라미터 타입 추론 문제 회피)
     * - AI 판정/유형 조건은 ai_results 에 EXISTS 서브쿼리
     * - 정렬은 Pageable 로 전달 (기본: startTime DESC)
     */
    @Query(value = """
            SELECT f FROM Flow f
            WHERE (:useSince = false OR f.startTime >= :since)
              AND (:srcIp = '' OR f.srcIp = :srcIp)
              AND (:destIp = '' OR f.destIp = :destIp)
              AND (:port < 0 OR f.destPort = :port)
              AND (:protocol = '' OR UPPER(f.protocol) = :protocol)
              AND (:q = '' OR f.srcIp LIKE :qLike OR f.destIp LIKE :qLike OR f.flowId = :qFlowId)
              AND (:verdict = ''
                   OR (:verdict = 'attack' AND EXISTS (
                         SELECT 1 FROM AiResult a WHERE a.flowId = f.flowId AND a.attackType <> 'Normal'))
                   OR (:verdict = 'normal' AND NOT EXISTS (
                         SELECT 1 FROM AiResult a WHERE a.flowId = f.flowId AND a.attackType <> 'Normal')))
              AND (:attackType = '' OR EXISTS (
                     SELECT 1 FROM AiResult t WHERE t.flowId = f.flowId AND t.attackType = :attackType))
            """,
            countQuery = """
            SELECT COUNT(f) FROM Flow f
            WHERE (:useSince = false OR f.startTime >= :since)
              AND (:srcIp = '' OR f.srcIp = :srcIp)
              AND (:destIp = '' OR f.destIp = :destIp)
              AND (:port < 0 OR f.destPort = :port)
              AND (:protocol = '' OR UPPER(f.protocol) = :protocol)
              AND (:q = '' OR f.srcIp LIKE :qLike OR f.destIp LIKE :qLike OR f.flowId = :qFlowId)
              AND (:verdict = ''
                   OR (:verdict = 'attack' AND EXISTS (
                         SELECT 1 FROM AiResult a WHERE a.flowId = f.flowId AND a.attackType <> 'Normal'))
                   OR (:verdict = 'normal' AND NOT EXISTS (
                         SELECT 1 FROM AiResult a WHERE a.flowId = f.flowId AND a.attackType <> 'Normal')))
              AND (:attackType = '' OR EXISTS (
                     SELECT 1 FROM AiResult t WHERE t.flowId = f.flowId AND t.attackType = :attackType))
            """)
    Page<Flow> search(@Param("useSince") boolean useSince,
                      @Param("since") LocalDateTime since,
                      @Param("srcIp") String srcIp,
                      @Param("destIp") String destIp,
                      @Param("port") int port,
                      @Param("protocol") String protocol,
                      @Param("q") String q,
                      @Param("qLike") String qLike,
                      @Param("qFlowId") long qFlowId,
                      @Param("verdict") String verdict,
                      @Param("attackType") String attackType,
                      Pageable pageable);
}
