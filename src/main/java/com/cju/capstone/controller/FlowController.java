package com.cju.capstone.controller;

import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.dto.AiResultDto;
import com.cju.capstone.dto.FlowDetailDto;
import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.service.FlowService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/flows")
@RequiredArgsConstructor
public class FlowController {

    private final FlowService flowService;

    @GetMapping
    public Page<FlowDto> getFlows(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        return flowService.getFlows(page, size);
    }

    @GetMapping("/{flowId}")
    public FlowDetailDto getFlow(@PathVariable Long flowId) {
        return flowService.getFlowDetail(flowId);
    }

    @GetMapping("/{flowId}/ai-results")
    public List<AiResultDto> getAiResults(@PathVariable Long flowId) {
        return flowService.getAiResults(flowId);
    }
}