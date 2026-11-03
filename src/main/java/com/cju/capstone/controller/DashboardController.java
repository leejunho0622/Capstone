package com.cju.capstone.controller;

import com.cju.capstone.dto.AttackTypeDto;
import com.cju.capstone.dto.DashboardSummaryDto;
import com.cju.capstone.dto.RealtimeDto;
import com.cju.capstone.dto.TimelineDto;
import com.cju.capstone.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    /** 상단 KPI */
    @GetMapping("/summary")
    public DashboardSummaryDto summary() {
        return dashboardService.getSummary();
    }

    /** 공격 유형 분포. period = all | today */
    @GetMapping("/attack-types")
    public List<AttackTypeDto> attackTypes(@RequestParam(defaultValue = "all") String period) {
        return dashboardService.getAttackTypes(period);
    }

    /** 최근 7일 일별 공격 건수 */
    @GetMapping("/timeline")
    public List<TimelineDto> timeline() {
        return dashboardService.getTimeline();
    }

    /** 최근 24시간 시간대별 공격 건수 */
    @GetMapping("/realtime")
    public List<RealtimeDto> realtime() {
        return dashboardService.getRealtime();
    }
}
