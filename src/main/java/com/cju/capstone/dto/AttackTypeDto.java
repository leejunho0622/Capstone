package com.cju.capstone.dto;

/** 공격 유형별 건수 (attack_events 기준) */
public record AttackTypeDto(
        String type,
        long count
) {
}
