package com.cju.capstone.controller;

import com.cju.capstone.dto.AiResultDto;
import com.cju.capstone.dto.FlowDetailDto;
import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.service.FlowService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** 트래픽(연결 단위, flows) API */
@RestController
@RequestMapping("/api/flows")
@RequiredArgsConstructor
public class FlowController {

    private final FlowService flowService;

    /**
     * 트래픽 검색 (최신순)
     * q: IP 앞부분 또는 Flow ID / verdict: attack | normal / hours: 최근 N시간
     */
    @GetMapping
    public Page<FlowDto> list(@RequestParam(required = false) String q,
                              @RequestParam(required = false) String srcIp,
                              @RequestParam(required = false) String destIp,
                              @RequestParam(required = false) Integer port,
                              @RequestParam(required = false) String protocol,
                              @RequestParam(required = false) String verdict,
                              @RequestParam(required = false) String attackType,
                              @RequestParam(required = false) Integer hours,
                              @RequestParam(defaultValue = "0") int page,
                              @RequestParam(defaultValue = "50") int size) {
        return flowService.search(
                new FlowService.SearchCondition(q, srcIp, destIp, port, protocol, verdict, attackType, hours),
                page, size);
    }

    @GetMapping("/{flowId}")
    public FlowDetailDto get(@PathVariable Long flowId) {
        return flowService.getDetail(flowId);
    }

    /** 분석 이력 (최신순) */
    @GetMapping("/{flowId}/ai-results")
    public List<AiResultDto> aiResults(@PathVariable Long flowId) {
        return flowService.getAiResults(flowId);
    }
}
