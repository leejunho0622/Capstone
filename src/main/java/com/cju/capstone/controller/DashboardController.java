package com.cju.capstone.controller;

import com.cju.capstone.dto.AttackTypeDto;
import com.cju.capstone.dto.DashboardSummaryDto;
import com.cju.capstone.dto.TimelineDto;
import com.cju.capstone.service.DashboardService;
import com.cju.capstone.service.FlowService;
import lombok.RequiredArgsConstructor;
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
    public List<AttackTypeDto> attackTypes() {
        return flowService.getAttackTypes();
    }

    @GetMapping("/timeline")
    public List<TimelineDto> timeline() {
        return flowService.getTimeline();
    }

    @GetMapping("/alerts")
    public List<String> alerts() {
        return List.of("High risk detected", "Suspicious IP");
    }

    @GetMapping("/realtime")
    public String realtime() {
        return "NORMAL";
    }
}