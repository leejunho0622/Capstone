package com.cju.capstone.repository;

import com.cju.capstone.domain.Flow;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 탐지 성능 집계 전용 (읽기 전용 네이티브 쿼리)
 * - IDS 탐지: flows.severity IS NOT NULL  (collector.py 가 Suricata alert 를 플로우에 매칭해 기록)
 * - AI 탐지 : ai_results.attack_type <> 'Normal'
 * MySQL 의 비교식은 0/1 을 돌려주므로 SUM(조건) 으로 건수를 셀 수 있다.
 */
public interface DetectionStatsRepository extends Repository<Flow, Long> {

    /**
     * 플로우 단위 교차표 [ids_hit(0/1), ai_hit(0/1), 건수] - AI 분석을 거친 플로우만
     * ai_results 는 기간으로 먼저 줄인 뒤(플로우별 공격 판정 여부) 조인
     */
    @Query(value = """
            SELECT (f.severity IS NOT NULL) AS ids_hit,
                   (x.attack_rows > 0)      AS ai_hit,
                   COUNT(*)
            FROM flows f
            JOIN (SELECT flow_id,
                         SUM(CASE WHEN attack_type <> 'Normal' THEN 1 ELSE 0 END) AS attack_rows
                  FROM ai_results
                  WHERE analyzed_at >= :since
                  GROUP BY flow_id) x ON x.flow_id = f.flow_id
            WHERE f.start_time >= :since
            GROUP BY ids_hit, ai_hit
            """, nativeQuery = true)
    List<Object[]> flowMatrix(@Param("since") LocalDateTime since);

    /** AI 공격 유형별 [유형, AI 탐지 플로우 수, 그중 IDS 도 탐지한 수] */
    @Query(value = """
            SELECT a.attack_type,
                   COUNT(DISTINCT f.flow_id),
                   COUNT(DISTINCT CASE WHEN f.severity IS NOT NULL THEN f.flow_id END)
            FROM flows f
            JOIN ai_results a ON a.flow_id = f.flow_id
            WHERE f.start_time >= :since AND a.attack_type <> 'Normal'
            GROUP BY a.attack_type
            """, nativeQuery = true)
    List<Object[]> flowsByType(@Param("since") LocalDateTime since);

    /** 공격 단위 [유형, 공격 수, IDS 가 그 공격의 플로우를 하나라도 잡은 공격 수] */
    @Query(value = """
            SELECT e.attack_type,
                   COUNT(*),
                   SUM(CASE WHEN d.attack_id IS NOT NULL THEN 1 ELSE 0 END)
            FROM attack_events e
            LEFT JOIN (SELECT DISTINCT attack_id
                       FROM flows
                       WHERE severity IS NOT NULL AND attack_id IS NOT NULL) d ON d.attack_id = e.id
            WHERE e.first_seen >= :since
            GROUP BY e.attack_type
            """, nativeQuery = true)
    List<Object[]> incidentsByType(@Param("since") LocalDateTime since);

    /** IDS 룰이 전혀 잡지 못한 공격 (AI 만 탐지) - 위험도 순 */
    @Query(value = """
            SELECT e.id
            FROM attack_events e
            WHERE e.first_seen >= :since
              AND NOT EXISTS (SELECT 1 FROM flows f WHERE f.attack_id = e.id AND f.severity IS NOT NULL)
            ORDER BY e.event_risk DESC, e.id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<Number> aiOnlyIncidentIds(@Param("since") LocalDateTime since, @Param("limit") int limit);

    /** IDS 룰은 잡았는데 AI 는 정상으로 본 플로우 (AI 미탐 후보) - 최신순 */
    @Query(value = """
            SELECT f.flow_id
            FROM flows f
            WHERE f.start_time >= :since
              AND f.severity IS NOT NULL
              AND EXISTS (SELECT 1 FROM ai_results r WHERE r.flow_id = f.flow_id)
              AND NOT EXISTS (SELECT 1 FROM ai_results a
                              WHERE a.flow_id = f.flow_id AND a.attack_type <> 'Normal')
            ORDER BY f.start_time DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<Number> idsOnlyFlowIds(@Param("since") LocalDateTime since, @Param("limit") int limit);

    // ---------------- 탐지 지연 ----------------

    /** 연결 종료 → AI 분석까지 걸린 초 (공격 판정만, 최근 순 최대 limit 건) */
    @Query(value = """
            SELECT TIMESTAMPDIFF(SECOND, f.end_time, a.analyzed_at)
            FROM ai_results a
            JOIN flows f ON f.flow_id = a.flow_id
            WHERE a.analyzed_at >= :since
              AND a.attack_type <> 'Normal'
              AND f.end_time IS NOT NULL
            ORDER BY a.analyzed_at DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<Number> flowLatencySeconds(@Param("since") LocalDateTime since, @Param("limit") int limit);

    /** 공격 시작(first_seen) → 그 공격의 첫 AI 판정까지 걸린 초 (공격별 1건) */
    @Query(value = """
            SELECT TIMESTAMPDIFF(SECOND, e.first_seen, MIN(a.analyzed_at))
            FROM attack_events e
            JOIN flows f ON f.attack_id = e.id
            JOIN ai_results a ON a.flow_id = f.flow_id
            WHERE e.first_seen >= :since
            GROUP BY e.id, e.first_seen
            """, nativeQuery = true)
    List<Number> incidentLatencySeconds(@Param("since") LocalDateTime since);
}
