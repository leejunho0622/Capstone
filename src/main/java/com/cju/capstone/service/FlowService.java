package com.cju.capstone.service;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.dto.*;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.FlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FlowService {

    private final FlowRepository flowRepository;
    private final AiResultRepository aiResultRepository;

    // 1. Flow 목록 (페이징)
    public Page<FlowDto> getFlows(int page, int size) {
        PageRequest pageable = PageRequest.of(page, size);

        return flowRepository.findAll(pageable)
                .map(FlowDto::from);
    }

    // 2. Flow 상세 조회
    public FlowDetailDto getFlowDetail(Long flowId) {

        Flow flow = flowRepository.findByFlowId(flowId)
                .orElseThrow(() -> new IllegalArgumentException("Flow not found: " + flowId));

        AiResult ai = aiResultRepository.findTopByFlow_FlowId(flowId)
                .orElse(null);

        return FlowDetailDto.of(flow, ai);
    }

    // 3. AI 결과 전체 조회
    public List<AiResultDto> getAiResults(Long flowId) {

        return aiResultRepository.findAllByFlow_FlowId(flowId)
                .stream()
                .map(AiResultDto::from)
                .toList();
    }

    public List<AttackTypeDto> getAttackTypes() {
        return aiResultRepository.countAttackTypes()
                .stream()
                .map(row -> new AttackTypeDto(
                        (String) row[0],
                        (Long) row[1]
                ))
                .toList();
    }

    public List<TimelineDto> getTimeline() {
        return aiResultRepository.getTimeline()
                .stream()
                .map(row -> new TimelineDto(
                        ((Number) row[0]).intValue(),   // hour
                        ((Number) row[1]).longValue()   // count
                ))
                .toList();
    }

    public List<Flow> getAllFlows() {
        return flowRepository.findAll();
    }
}