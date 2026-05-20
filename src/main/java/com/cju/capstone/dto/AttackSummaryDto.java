package com.cju.capstone.dto;

public record AttackSummaryDto(
        String srcIp,
        String attackType,
        Long count
) {}