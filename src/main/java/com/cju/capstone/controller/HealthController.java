package com.cju.capstone.controller;

import com.cju.capstone.config.SchemaCheck;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 연동 점검용: 브라우저에서 http://localhost:8080/api/health
 * DB 접속, 필요한 테이블 존재 여부, 테이블별 행 수, DB 서버 시각을 한 번에 확인
 */
@RestController
@RequiredArgsConstructor
public class HealthController {

    private final JdbcTemplate jdbc;
    private final SchemaCheck schemaCheck;

    @GetMapping("/api/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server", "UP");
        out.put("serverTime", LocalDateTime.now().toString());
        try {
            out.put("dbTime", String.valueOf(jdbc.queryForObject("SELECT NOW()", Object.class)));
            out.put("db", "UP");
            Map<String, Boolean> tables = schemaCheck.tables();
            out.put("tables", tables);
            Map<String, Object> rows = new LinkedHashMap<>();
            for (Map.Entry<String, Boolean> t : tables.entrySet()) {
                rows.put(t.getKey(), t.getValue()
                        ? jdbc.queryForObject("SELECT COUNT(*) FROM " + t.getKey(), Long.class)
                        : "테이블 없음");
            }
            out.put("rows", rows);
        } catch (Exception e) {
            out.put("db", "DOWN");
            out.put("error", e.getMessage());
        }
        return out;
    }
}
