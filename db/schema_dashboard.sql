-- ============================================================
-- 관제 대시보드(백엔드)용 추가 스키마
--   1) incident_triage : 관제요원의 경보 처리 기록 (신규/확인 중/조치 완료/오탐)
--   2) 조회 성능용 인덱스 (최신순 정렬·기간 조회에 사용)
--
-- 실행 (1회만):
--   mysql -u ids_user -p ids_db < schema_dashboard.sql
--
-- ※ attack_events.status(open/closed) 는 AI 파이프라인이 관리하는 '공격 진행 여부'
--   incident_triage.status 는 사람이 관리하는 '처리 상태' → 서로 다른 값이라 테이블을 분리
-- ============================================================

-- 1) 경보 처리 기록 -------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_triage (
    attack_id  BIGINT       PRIMARY KEY COMMENT 'attack_events.id',
    status     VARCHAR(20)  NOT NULL DEFAULT 'NEW' COMMENT 'NEW / ACK / RESOLVED / FALSE_POSITIVE',
    note       TEXT         NULL     COMMENT '분석 메모',
    assignee   VARCHAR(50)  NULL     COMMENT '처리한 관제요원',
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_triage_status (status),
    CONSTRAINT fk_triage_attack
        FOREIGN KEY (attack_id) REFERENCES attack_events(id)
        ON DELETE CASCADE
);

-- 2) 조회 성능 인덱스 -----------------------------------------------
--    MySQL 은 CREATE INDEX IF NOT EXISTS 가 없어 두 번 실행하면
--    "Duplicate key name" 오류가 나지만 데이터에는 영향 없음.

-- 트래픽 목록: ORDER BY start_time DESC + 기간 조회
CREATE INDEX idx_flows_start_time ON flows (start_time);

-- 경보 목록: 최근 활동(last_seen) 기준 조회/정렬
CREATE INDEX idx_events_last_seen ON attack_events (last_seen);

-- 플로우별 최신 AI 결과 조회
CREATE INDEX idx_ai_flow_analyzed ON ai_results (flow_id, analyzed_at);
