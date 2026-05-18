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

    @Query(value = """
    SELECT attack_type, COUNT(*)
    FROM ai_results
    WHERE analyzed_at >= NOW() - INTERVAL 7 DAY
    GROUP BY attack_type
""", nativeQuery = true)
    List<Object[]> countAttackTypesWeek();

    @Query(value = """
    SELECT attack_type, COUNT(*)
    FROM ai_results
    GROUP BY attack_type
""", nativeQuery = true)
    List<Object[]> countAttackTypesAll();

    @Query(value = """
    SELECT
        t.day_date,
        COUNT(a.id) AS count
    FROM (
        SELECT CURDATE() - INTERVAL 6 DAY AS day_date UNION ALL
        SELECT CURDATE() - INTERVAL 5 DAY UNION ALL
        SELECT CURDATE() - INTERVAL 4 DAY UNION ALL
        SELECT CURDATE() - INTERVAL 3 DAY UNION ALL
        SELECT CURDATE() - INTERVAL 2 DAY UNION ALL
        SELECT CURDATE() - INTERVAL 1 DAY UNION ALL
        SELECT CURDATE()
    ) t
    LEFT JOIN ai_results a
        ON DATE(a.analyzed_at) = t.day_date
    GROUP BY t.day_date
    ORDER BY t.day_date
""", nativeQuery = true)
    List<Object[]> getTimeline();

    @Query(value = """
    SELECT
        t.hour,
        COUNT(a.id) AS count
    FROM (
        SELECT 0 AS hour UNION ALL
        SELECT 1 UNION ALL
        SELECT 2 UNION ALL
        SELECT 3 UNION ALL
        SELECT 4 UNION ALL
        SELECT 5 UNION ALL
        SELECT 6 UNION ALL
        SELECT 7 UNION ALL
        SELECT 8 UNION ALL
        SELECT 9 UNION ALL
        SELECT 10 UNION ALL
        SELECT 11 UNION ALL
        SELECT 12 UNION ALL
        SELECT 13 UNION ALL
        SELECT 14 UNION ALL
        SELECT 15 UNION ALL
        SELECT 16 UNION ALL
        SELECT 17 UNION ALL
        SELECT 18 UNION ALL
        SELECT 19 UNION ALL
        SELECT 20 UNION ALL
        SELECT 21 UNION ALL
        SELECT 22 UNION ALL
        SELECT 23
    ) t
    LEFT JOIN ai_results a
        ON HOUR(a.analyzed_at) = t.hour
        AND a.analyzed_at >= NOW() - INTERVAL 24 HOUR
    GROUP BY t.hour
    ORDER BY t.hour
""", nativeQuery = true)
    List<Object[]> getRealtime();

    List<AiResult> findAllByFlow_FlowIdIn(List<Long> flowIds);
}