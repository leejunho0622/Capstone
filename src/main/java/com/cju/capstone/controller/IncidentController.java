package com.cju.capstone.controller;

import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.dto.IncidentDto;
import com.cju.capstone.dto.TriageDto;
import com.cju.capstone.dto.TriageRequest;
import com.cju.capstone.service.IncidentService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

/** 경보(공격 단위, attack_events) API */
@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;

    /** 최근 N시간 안에 활동한 공격 목록 (최근 활동순) */
    @GetMapping
    public Page<IncidentDto> list(@RequestParam(defaultValue = "24") int hours,
                                  @RequestParam(required = false) String attackType,
                                  @RequestParam(required = false) String q,
                                  @RequestParam(defaultValue = "0") int page,
                                  @RequestParam(defaultValue = "50") int size) {
        return incidentService.list(hours, attackType, q, page, size);
    }

    @GetMapping("/{id}")
    public IncidentDto get(@PathVariable Long id) {
        return incidentService.get(id);
    }

    /** 이 공격에 묶인 플로우 (v_attack_flows 와 같은 범위) */
    @GetMapping("/{id}/flows")
    public Page<FlowDto> flows(@PathVariable Long id,
                               @RequestParam(defaultValue = "0") int page,
                               @RequestParam(defaultValue = "20") int size) {
        return incidentService.flows(id, page, size);
    }

    /** 처리 상태 저장: { "status": "ACK", "note": "...", "assignee": "홍길동" } */
    @PutMapping("/{id}/triage")
    public TriageDto saveTriage(@PathVariable Long id, @RequestBody TriageRequest request) {
        return incidentService.saveTriage(id, request);
    }
}
