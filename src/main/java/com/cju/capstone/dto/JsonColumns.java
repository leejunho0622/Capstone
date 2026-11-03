package com.cju.capstone.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * DB JSON 컬럼(문자열) → JSON 객체 변환.
 * 응답에 문자열 "{\"a\":1}" 이 아니라 객체 {"a":1} 로 내려가도록 한다.
 */
public final class JsonColumns {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonColumns() {
    }

    public static JsonNode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            // 형식이 깨진 값이어도 화면에서 원문을 볼 수 있게 문자열로 전달
            return TextNode.valueOf(raw);
        }
    }
}
