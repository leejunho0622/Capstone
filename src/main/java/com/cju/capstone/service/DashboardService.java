package com.cju.capstone.service;

import com.cju.capstone.config.AttackType;
import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;
import com.cju.capstone.dto.*;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.FlowFlagsRepository;
import com.cju.capstone.repository.FlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DashboardService {

    private final FlowRepository flowRepository;
    private final FlowFlagsRepository flowFlagsRepository;
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

    public List<AttackTypeDto> getAttackTypes(String period) {

        List<Object[]> result;

        if ("week".equals(period)) {
            result = aiResultRepository.countAttackTypesWeek();
        } else {
            result = aiResultRepository.countAttackTypesAll();
        }

        Map<String, Long> counts = new HashMap<>();

        for (Object[] row : result) {
            counts.put(
                    (String) row[0],
                    ((Number) row[1]).longValue()
            );
        }

        return Arrays.stream(AttackType.values())
                .map(type -> new AttackTypeDto(
                        type.name(),
                        counts.getOrDefault(
                                type.name(),
                                0L
                        )
                ))
                .toList();
    }

    public List<TimelineDto> getTimeline() {
        return aiResultRepository.getTimeline()
                .stream()
                .map(row -> new TimelineDto(
                        ((java.sql.Date) row[0])
                                .toLocalDate()
                                .format(DateTimeFormatter.ofPattern("MM/dd")),
                        ((Number) row[1]).longValue()
                ))
                .toList();
    }

    public List<RealtimeDto> getRealtime() {
        return aiResultRepository.getRealtime()
                .stream()
                .map(row -> new RealtimeDto(
                        ((Number) row[0]).intValue(),
                        ((Number) row[1]).longValue()
                ))
                .toList();
    }

    public Page<AttackFlowDto> getAttackFlows(int page, int size) {

        Pageable pageable = PageRequest.of(page, size);

        Page<Flow> flowPage = flowRepository.findAttackFlows(pageable);

        if (flowPage.isEmpty()) {
            return Page.empty(pageable);
        }

        // flowId 목록
        List<Long> flowIds = flowPage.getContent().stream()
                .map(Flow::getFlowId)
                .toList();

        // flags 조회
        List<FlowFlags> flagsList =
                flowFlagsRepository.findAllByFlowIdIn(flowIds);

        // ai 조회
        List<AiResult> aiResults =
                aiResultRepository.findAllByFlow_FlowIdIn(flowIds);

        // flags map
        Map<Long, FlowFlags> flagsMap = flagsList.stream()
                .collect(Collectors.toMap(
                        FlowFlags::getFlowId,
                        f -> f
                ));

        // ai map
        Map<Long, AiResult> aiMap = aiResults.stream()
                .collect(Collectors.toMap(
                        ai -> ai.getFlow().getFlowId(),
                        a -> a
                ));

        return flowPage.map(flow -> {

            FlowFlags flags =
                    flagsMap.get(flow.getFlowId());

            AiResult ai =
                    aiMap.get(flow.getFlowId());

            return AttackFlowDto.of(
                    FlowDto.from(flow, flags),
                    ai != null ? AiResultDto.from(ai) : null
            );
        });
    }
}