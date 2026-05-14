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

    // 🔥 fetch join (전체 조회용)
    @Query("""
    SELECT f FROM Flow f
    LEFT JOIN FETCH f.flowFlags
    """)
    List<Flow> findAllWithFlags();

    // 🔥 fetch join (단건 조회용)
    @Query("""
    SELECT f FROM Flow f
    LEFT JOIN FETCH f.flowFlags
    WHERE f.flowId = :flowId
    """)
    Optional<Flow> findWithFlags(Long flowId);

    @Query(value = """
        SELECT COUNT(*) FROM flows
        WHERE DATE(start_time) = CURDATE()
    """, nativeQuery = true)
    long countTodayAttacks();

    @Query("""
    SELECT new com.cju.capstone.dto.TimelineDto(
        FUNCTION('HOUR', f.startTime),
        COUNT(f)
    )
    FROM Flow f
    GROUP BY FUNCTION('HOUR', f.startTime)
    """)
    List<TimelineDto> groupByHour();

    @Query("""
    SELECT f
    FROM Flow f
    WHERE EXISTS (
        SELECT 1
        FROM AiResult a
        WHERE a.flow.flowId = f.flowId
    )
    ORDER BY f.startTime DESC
    """)
    Page<Flow> findAttackFlows(Pageable pageable);
}