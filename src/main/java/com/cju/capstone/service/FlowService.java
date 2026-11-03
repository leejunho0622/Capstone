package com.cju.capstone.service;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;
import com.cju.capstone.dto.AiResultDto;
import com.cju.capstone.dto.FlowDetailDto;
import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.FlowFlagsRepository;
import com.cju.capstone.repository.FlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class FlowService {

    public static final int MAX_PAGE_SIZE = 500;

    private final FlowRepository flowRepository;
    private final FlowFlagsRepository flowFlagsRepository;
    private final AiResultRepository aiResultRepository;

    /** 트래픽 검색 조건 (컨트롤러에서 받은 값 그대로, 빈 값 허용) */
    public record SearchCondition(
            String q, String srcIp, String destIp, Integer port, String protocol,
            String verdict, String attackType, Integer hours
    ) {
    }

    /** 트래픽 목록 (최신순). 페이지당 쿼리 3회 고정: flows / flow_flags IN / ai_results IN */
    public Page<FlowDto> search(SearchCondition c, int page, int size) {
        String q = trim(c.q());
        boolean numericQ = !q.isEmpty() && q.chars().allMatch(Character::isDigit) && q.length() < 19;
        boolean useSince = c.hours() != null && c.hours() > 0;
        LocalDateTime since = useSince ? LocalDateTime.now().minusHours(c.hours()) : LocalDateTime.of(1970, 1, 1, 0, 0);

        Page<Flow> flows = flowRepository.search(
                useSince,
                since,
                trim(c.srcIp()),
                trim(c.destIp()),
                c.port() != null ? c.port() : -1,
                trim(c.protocol()).toUpperCase(Locale.ROOT),
                q,
                q + "%",
                numericQ ? Long.parseLong(q) : -1L,
                normalizeVerdict(c.verdict()),
                trim(c.attackType()),
                pageable(page, size));

        return toDtoPage(flows);
    }

    /** 한 공격에 묶인 플로우 (시간순) */
    public Page<FlowDto> findByAttack(Long attackId, int page, int size) {
        Page<Flow> flows = flowRepository.findByAttackId(attackId,
                PageRequest.of(Math.max(0, page), clampSize(size), Sort.by(Sort.Direction.DESC, "startTime")));
        return toDtoPage(flows);
    }

    public FlowDetailDto getDetail(Long flowId) {
        Flow flow = flowRepository.findByFlowId(flowId)
                .orElseThrow(() -> new NotFoundException("Flow not found: " + flowId));
        FlowFlags flags = flowFlagsRepository.findById(flowId).orElse(null);
        AiResult ai = aiResultRepository.findFirstByFlowIdOrderByAnalyzedAtDescIdDesc(flowId).orElse(null);
        return FlowDetailDto.of(flow, flags, ai);
    }

    public List<AiResultDto> getAiResults(Long flowId) {
        return aiResultRepository.findAllByFlowIdOrderByAnalyzedAtDescIdDesc(flowId).stream()
                .map(AiResultDto::from)
                .toList();
    }

    // ------------------------------------------------------------------

    private Page<FlowDto> toDtoPage(Page<Flow> flows) {
        if (flows.isEmpty()) {
            return flows.map(f -> FlowDto.of(f, null, null));
        }
        List<Long> ids = flows.getContent().stream().map(Flow::getFlowId).toList();

        Map<Long, FlowFlags> flagsById = flowFlagsRepository.findAllByFlowIdIn(ids).stream()
                .collect(Collectors.toMap(FlowFlags::getFlowId, Function.identity(), (a, b) -> a));

        // 한 플로우에 결과가 여러 개면 가장 최근 분석 결과 사용 (중복 키 예외 방지)
        Map<Long, AiResult> latestAi = aiResultRepository.findAllByFlowIdIn(ids).stream()
                .collect(Collectors.toMap(AiResult::getFlowId, Function.identity(), FlowService::newer));

        return flows.map(f -> FlowDto.of(f, flagsById.get(f.getFlowId()), latestAi.get(f.getFlowId())));
    }

    private static AiResult newer(AiResult a, AiResult b) {
        Comparator<AiResult> byTime = Comparator
                .comparing(AiResult::getAnalyzedAt, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(AiResult::getId, Comparator.nullsFirst(Comparator.naturalOrder()));
        return byTime.compare(a, b) >= 0 ? a : b;
    }

    private static PageRequest pageable(int page, int size) {
        return PageRequest.of(Math.max(0, page), clampSize(size),
                Sort.by(Sort.Direction.DESC, "startTime").and(Sort.by(Sort.Direction.DESC, "flowId")));
    }

    static int clampSize(int size) {
        return Math.min(MAX_PAGE_SIZE, Math.max(1, size));
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    private static String normalizeVerdict(String v) {
        String s = trim(v).toLowerCase(Locale.ROOT);
        return s.equals("attack") || s.equals("normal") ? s : "";
    }
}
