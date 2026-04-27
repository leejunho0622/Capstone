package com.cju.capstone.repository;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.dto.AlertDto;
import com.cju.capstone.dto.AttackTypeDto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AiResultRepository extends JpaRepository<AiResult, Long> {

    // Flow FK 기반 조회 (JPA 규칙: _Id 붙이면 자동으로 flow.id 탐색)
    Optional<AiResult> findTopByFlow_FlowId(Long flowId);

    List<AiResult> findAllByFlow_FlowId(Long flowId);

    @Query("""
        SELECT AVG(a.riskScore)
        FROM AiResult a
    """)
    double avgRiskScore();

    @Query("""
        SELECT COUNT(a) > 0
        FROM AiResult a
        WHERE a.riskScore > 80
        AND a.analyzedAt > CURRENT_TIMESTAMP - 1 MINUTE
    """)
    boolean existsHighRiskRecent();

    @Query("""
        SELECT new com.cju.capstone.dto.AttackTypeDto(a.attackType, COUNT(a))
        FROM AiResult a
        GROUP BY a.attackType
    """)
    List<AttackTypeDto> groupByAttackType();

    @Query("""
        SELECT new com.cju.capstone.dto.AlertDto(
            a.flow.id,
            a.riskScore,
            a.attackType
        )
        FROM AiResult a
        WHERE a.riskScore > 80
        ORDER BY a.analyzedAt DESC
    """)
    List<AlertDto> findHighRiskAlerts();

    @Query("""
        SELECT a.attackType, COUNT(a)
        FROM AiResult a
        GROUP BY a.attackType
        """)
    List<Object[]> countAttackTypes();

    @Query(value = """
        SELECT 
            t.hour,
            COUNT(a.id) AS count
        FROM (
            SELECT 0 AS hour UNION ALL
            SELECT 4 UNION ALL
            SELECT 8 UNION ALL
            SELECT 12 UNION ALL
            SELECT 16 UNION ALL
            SELECT 20
        ) t
        LEFT JOIN ai_results a
            ON FLOOR(HOUR(a.analyzed_at)/4)*4 = t.hour
            AND a.analyzed_at >= CURDATE()
            AND a.analyzed_at < CURDATE() + INTERVAL 1 DAY
        GROUP BY t.hour
        ORDER BY t.hour
""", nativeQuery = true)
    List<Object[]> getTimeline();
}