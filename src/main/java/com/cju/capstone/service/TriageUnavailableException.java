package com.cju.capstone.service;

/** incident_triage 테이블이 아직 없을 때 → 503 (프론트는 브라우저 저장 모드로 전환) */
public class TriageUnavailableException extends RuntimeException {
    public TriageUnavailableException() {
        super("incident_triage 테이블이 없습니다. db/schema_dashboard.sql 을 실행하세요.");
    }
}
