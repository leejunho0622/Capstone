package com.cju.capstone.repository;

import com.cju.capstone.domain.IncidentTriage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

import java.util.Collection;
import java.util.List;

public interface IncidentTriageRepository extends JpaRepository<IncidentTriage, Long> {

    List<IncidentTriage> findAllByAttackIdIn(Collection<Long> attackIds);

    /** 관제요원 판정 결과 [공격 유형, 처리 상태, 건수] - 기간 안에 시작된 공격 기준 */
    @Query("""
            SELECT e.attackType, t.status, COUNT(t)
            FROM IncidentTriage t, AttackEvent e
            WHERE t.attackId = e.id AND e.firstSeen >= :since
            GROUP BY e.attackType, t.status
            """)
    List<Object[]> outcomeByType(@Param("since") LocalDateTime since);
}
