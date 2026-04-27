package com.cju.capstone.dto;

public record DashboardSummaryDto(
        long totalFlows,
        long todayAttacks,
        boolean realtimeAttack,
        double avgRisk
) {}