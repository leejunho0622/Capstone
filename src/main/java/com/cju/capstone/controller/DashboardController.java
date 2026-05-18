package com.cju.capstone.controller;

import com.cju.capstone.dto.*;
import com.cju.capstone.service.DashboardService;
import com.cju.capstone.service.FlowService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;
    private final FlowService flowService;
    
    @GetMapping("/summary")
    public DashboardSummaryDto summary() {
        return dashboardService.getSummary();
    }

    @GetMapping("/attack-types")
    public List<AttackTypeDto> getAttackTypes(
            @RequestParam(defaultValue = "all") String period
    ) {
        return dashboardService.getAttackTypes(period);
    }

    @GetMapping("/timeline")
    public List<TimelineDto> timeline() {
        return dashboardService.getTimeline();
    }

    @GetMapping("/alerts")
    public Page<AttackFlowDto> alerts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size) {

        return dashboardService.getAttackFlows(page, size);
    }

    @GetMapping("/realtime")
    public List<RealtimeDto> realtime() {
        return dashboardService.getRealtime();
    }
}