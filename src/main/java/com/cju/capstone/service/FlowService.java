package com.cju.capstone.service;

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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class FlowService {

    private final FlowRepository flowRepository;
    private final FlowFlagsRepository flowFlagsRepository;
    private final AiResultRepository aiResultRepository;

    // 1. Flow 목록 (페이징)
    public Page<FlowDto> getFlows(int page, int size) {

        PageRequest pageable = PageRequest.of(page, size);

        // 1. Flow 페이징 조회
        Page<Flow> flowPage = flowRepository.findAll(pageable);

        // 🔥 데이터 없을 때 불필요 쿼리 방지
        if (flowPage.isEmpty()) {
            return flowPage.map(flow -> FlowDto.from(flow, null));
        }

        // 2. flowId 추출
        List<Long> flowIds = flowPage.getContent().stream()
                .map(Flow::getFlowId)
                .toList();

        // 3. flags 조회
        List<FlowFlags> flagsList = flowFlagsRepository.findAllByFlowIdIn(flowIds);

        // 중복 키 방어
        Map<Long, FlowFlags> flagsMap = flagsList.stream()
                .collect(Collectors.toMap(
                        FlowFlags::getFlowId,
                        f -> f,
                        (existing, replacement) -> existing
                ));

        // 4. DTO 변환
        return flowPage.map(flow -> {
            FlowFlags flags = flagsMap.get(flow.getFlowId());
            return FlowDto.from(flow, flags);
        });
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

    public List<Flow> getAllFlows() {
        return flowRepository.findAll();
    }
}