package com.cju.capstone.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DB 에 필요한 테이블이 있는지 확인
 * - incident_triage 는 db/schema_dashboard.sql 로 따로 만드는 테이블이라,
 *   아직 실행하지 않았으면 경보 목록 조회까지 실패하지 않도록 '없음'으로 처리한다.
 * - 없다고 판단한 뒤에도 30초마다 다시 확인 → SQL 을 실행하면 서버 재시작 없이 바로 사용
 */
@Component
public class SchemaCheck {

    private static final Logger log = LoggerFactory.getLogger(SchemaCheck.class);
    private static final long RECHECK_MS = 30_000;
    private static final List<String> REQUIRED = List.of(
            "flows", "flow_flags", "ai_results", "attack_events", "incident_triage");

    private final JdbcTemplate jdbc;
    private volatile Boolean triageAvailable;
    private volatile long checkedAt;

    public SchemaCheck(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean triageAvailable() {
        long now = System.currentTimeMillis();
        Boolean cached = triageAvailable;
        if (cached == null || (!cached && now - checkedAt > RECHECK_MS)) {
            boolean exists = tableExists("incident_triage");
            if (!exists && cached == null) {
                log.warn("incident_triage 테이블이 없습니다. db/schema_dashboard.sql 을 실행하면 경보 처리 상태가 서버에 저장됩니다.");
            }
            triageAvailable = exists;
            checkedAt = now;
            return exists;
        }
        return cached;
    }

    /** /api/health 용: 필요한 테이블별 존재 여부 */
    public Map<String, Boolean> tables() {
        Map<String, Boolean> result = new LinkedHashMap<>();
        for (String t : REQUIRED) {
            result.put(t, tableExists(t));
        }
        return result;
    }

    private boolean tableExists(String table) {
        try {
            Integer n = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
                    Integer.class, table);
            return n != null && n > 0;
        } catch (Exception e) {
            log.warn("테이블 확인 실패 ({}): {}", table, e.getMessage());
            return false;
        }
    }
}
