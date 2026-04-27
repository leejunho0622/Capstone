package com.cju.capstone.service;

import com.cju.capstone.dto.AlertDto;
import com.cju.capstone.dto.AttackTypeDto;
import com.cju.capstone.dto.DashboardSummaryDto;
import com.cju.capstone.dto.TimelineDto;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.FlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DashboardService {

    private final FlowRepository flowRepository;
    private final AiResultRepository aiResultRepository;

    public DashboardSummaryDto getSummary() {
        long totalFlows = flowRepository.count();
        long todayAttacks = flowRepository.countTodayAttacks();

        double avgRisk = aiResultRepository.avgRiskScore();

        boolean realtimeAttack = aiResultRepository.existsHighRiskRecent();

        return new DashboardSummaryDto(
                totalFlows,
                todayAttacks,
                realtimeAttack,
                avgRisk
        );
    }

    public List<AttackTypeDto> getAttackTypes() {
        return aiResultRepository.groupByAttackType();
    }

    public List<TimelineDto> getTimeline() {
        return flowRepository.groupByHour();
    }

    public List<AlertDto> getAlerts() {
        return aiResultRepository.findHighRiskAlerts();
    }
}