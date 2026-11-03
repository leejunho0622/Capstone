package com.cju.capstone.dto;

/** 최근 24시간 시간대별 공격 건수 (hour = 0~23) */
public record RealtimeDto(
        int hour,
        long count
) {
}
