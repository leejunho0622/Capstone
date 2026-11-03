package com.cju.capstone.dto;

/** PUT /api/incidents/{id}/triage 요청 본문 */
public record TriageRequest(
        String status,   // NEW / ACK / RESOLVED / FALSE_POSITIVE
        String note,
        String assignee
) {
}
