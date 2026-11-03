package com.cju.capstone.dto;

import com.cju.capstone.domain.IncidentTriage;

import java.time.LocalDateTime;

/** 경보 처리 상태 */
public record TriageDto(
        Long attackId,
        String status,
        String note,
        String assignee,
        LocalDateTime updatedAt
) {
    public static TriageDto from(IncidentTriage t) {
        if (t == null) {
            return null;
        }
        return new TriageDto(t.getAttackId(), t.getStatus().name(), t.getNote(), t.getAssignee(), t.getUpdatedAt());
    }
}
