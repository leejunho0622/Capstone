package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * incident_triage : 관제요원의 경보 처리 기록 (db/schema_dashboard.sql 로 생성)
 * 백엔드가 쓰기 권한을 갖는 유일한 테이블.
 */
@Entity
@Table(name = "incident_triage")
@Getter
@NoArgsConstructor
public class IncidentTriage {

    public enum Status { NEW, ACK, RESOLVED, FALSE_POSITIVE }

    @Id
    @Column(name = "attack_id")
    private Long attackId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status;

    @Column(columnDefinition = "TEXT")
    private String note;

    @Column(length = 50)
    private String assignee;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public IncidentTriage(Long attackId) {
        this.attackId = attackId;
        this.status = Status.NEW;
    }

    public void update(Status status, String note, String assignee) {
        this.status = status;
        this.note = note;
        this.assignee = assignee;
        this.updatedAt = LocalDateTime.now();
    }
}
