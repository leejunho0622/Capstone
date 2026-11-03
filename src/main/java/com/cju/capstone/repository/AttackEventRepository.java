package com.cju.capstone.repository;

import com.cju.capstone.domain.AttackEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AttackEventRepository extends JpaRepository<AttackEvent, Long> {

    /**
     * 경보 목록: 기간 안에 '활동한'(last_seen) 공격
     * attackType/q 는 '' 이면 무시. q 는 대표 출발지/목적지 IP 앞부분 일치
     */
    @Query("""
            SELECT e FROM AttackEvent e
            WHERE e.lastSeen >= :since
              AND (:attackType = '' OR e.attackType = :attackType)
              AND (:q = '' OR e.srcIp LIKE :qLike OR e.destIp LIKE :qLike)
            """)
    Page<AttackEvent> search(@Param("since") LocalDateTime since,
                             @Param("attackType") String attackType,
                             @Param("q") String q,
                             @Param("qLike") String qLike,
                             Pageable pageable);

    long countByFirstSeenGreaterThanEqual(LocalDateTime since);

    long countByState(String state);

    /** 실시간 공격 여부: 진행 중(open)이면서 최근에도 플로우가 붙고 있는 공격이 있는가 */
    boolean existsByStateAndLastSeenGreaterThanEqual(String state, LocalDateTime since);

    @Query("SELECT COALESCE(AVG(e.eventRisk), 0.0) FROM AttackEvent e WHERE e.firstSeen >= :since")
    Double averageEventRiskSince(@Param("since") LocalDateTime since);

    @Query("SELECT COALESCE(MAX(e.eventRisk), 0.0) FROM AttackEvent e WHERE e.firstSeen >= :since")
    Double maxEventRiskSince(@Param("since") LocalDateTime since);

    /** 유형별 공격 건수 [attackType, count] */
    @Query("""
            SELECT e.attackType, COUNT(e) FROM AttackEvent e
            WHERE e.firstSeen >= :since
            GROUP BY e.attackType
            """)
    List<Object[]> countByTypeSince(@Param("since") LocalDateTime since);

    /**
     * 기간 안의 공격 시작 시각 목록 → 일별/시간대별 집계는 서비스에서 수행
     * (DATE()/HOUR() 네이티브 함수 결과 타입이 드라이버마다 달라 생기던 ClassCastException 방지.
     *  공격 단위 행이라 건수가 많지 않음)
     */
    @Query("SELECT e.firstSeen FROM AttackEvent e WHERE e.firstSeen >= :since")
    List<LocalDateTime> findFirstSeenSince(@Param("since") LocalDateTime since);
}
