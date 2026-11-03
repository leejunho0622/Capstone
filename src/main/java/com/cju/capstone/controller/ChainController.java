package com.cju.capstone.controller;

import com.cju.capstone.dto.ChainDto;
import com.cju.capstone.service.ChainService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 공격 연관 분석 API */
@RestController
@RequestMapping("/api/chains")
@RequiredArgsConstructor
public class ChainController {

    private final ChainService chainService;

    /**
     * 같은 출발지에서 이어진 공격 묶음
     * hours: 조회 기간, gap: 이 시간(분) 이상 비면 다른 체인, minEvents: 체인으로 볼 최소 공격 수
     */
    @GetMapping
    public List<ChainDto> chains(@RequestParam(defaultValue = "24") int hours,
                                 @RequestParam(defaultValue = "30") int gap,
                                 @RequestParam(defaultValue = "2") int minEvents) {
        return chainService.findChains(hours, gap, minEvents);
    }
}
