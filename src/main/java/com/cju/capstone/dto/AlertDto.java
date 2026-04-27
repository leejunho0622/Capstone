package com.cju.capstone.dto;

public record AlertDto(
        Long flowId,
        String attackType,
        Double riskScore,
        String action
) {}