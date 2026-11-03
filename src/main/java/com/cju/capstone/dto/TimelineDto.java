package com.cju.capstone.dto;

/** 최근 7일 일별 공격 건수 (day = "MM/dd") */
public record TimelineDto(
        String day,
        long count
) {
}
