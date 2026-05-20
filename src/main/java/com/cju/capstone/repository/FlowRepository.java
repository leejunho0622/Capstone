package com.cju.capstone.repository;

import com.cju.capstone.domain.Flow;
import com.cju.capstone.dto.TimelineDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface FlowRepository extends JpaRepository<Flow, Long> {

    Optional<Flow> findByFlowId(Long flowId);

    @Query("""
    SELECT f
    FROM Flow f
    WHERE DATE(f.startTime) = CURRENT_DATE
    AND EXISTS (
        SELECT 1
        FROM AiResult a
        WHERE a.flow.flowId = f.flowId
    )
    ORDER BY f.startTime DESC
    """)
    Page<Flow> findAttackFlows(Pageable pageable);

    @Query("""
    SELECT
        f.srcIp,
        a.attackType,
        COUNT(f)
    FROM Flow f
    JOIN AiResult a
    ON f.flowId = a.flow.flowId
    
    WHERE DATE(f.startTime) = CURRENT_DATE
    
    GROUP BY
        f.srcIp,
        a.attackType
    
    ORDER BY
        COUNT(f) DESC
    """)
    List<Object[]> getAttackSummary();

    @Query(value = """
    SELECT COUNT(*)
    FROM (
        SELECT DATE(f.start_time),
               f.src_ip,
               a.attack_type,
               FLOOR(UNIX_TIMESTAMP(f.start_time)/60)
        FROM flows f
        JOIN ai_results a
        ON f.flow_id=a.flow_id
        WHERE DATE(f.start_time)=CURDATE()
        GROUP BY DATE(f.start_time),
                 f.src_ip,
                 a.attack_type,
                 FLOOR(UNIX_TIMESTAMP(f.start_time)/60)
    )t
    """, nativeQuery = true)
    Long countTodayIncidents();

    @Query(value = """
    SELECT day, COUNT(*)
    FROM (
        SELECT DATE(f.start_time) day,
               f.src_ip,
               a.attack_type,
               FLOOR(UNIX_TIMESTAMP(f.start_time)/60)
        FROM flows f
        JOIN ai_results a ON f.flow_id=a.flow_id
        WHERE DATE(f.start_time) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
          AND DATE(f.start_time) <= CURDATE()
        GROUP BY DATE(f.start_time),
                 f.src_ip,
                 a.attack_type,
                 FLOOR(UNIX_TIMESTAMP(f.start_time)/60)
    )t
    GROUP BY day
    ORDER BY day
    """, nativeQuery = true)
    List<Object[]> getIncidentTimeline();
}