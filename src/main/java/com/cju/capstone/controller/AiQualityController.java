package com.cju.capstone.controller;

import com.cju.capstone.dto.AiQualityDto;
import com.cju.capstone.dto.DetectionDto;
import com.cju.capstone.service.AiQualityService;
import com.cju.capstone.service.DetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;

/** AI 판정 품질 API */
@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
public class AiQualityController {

    private final AiQualityService aiQualityService;
    private final DetectionService detectionService;

    /** IDS 룰 탐지 vs AI 탐지 비교 */
    @GetMapping("/ids-comparison")
    public DetectionDto.IdsComparison idsComparison(@RequestParam(defaultValue = "7") int days) {
        return detectionService.idsComparison(days);
    }

    /** 탐지 지연: 공격 시작 → 첫 판정, 연결 종료 → 분석 */
    @GetMapping("/latency")
    public DetectionDto.Latency latency(@RequestParam(defaultValue = "7") int days) {
        return detectionService.latency(days);
    }

    /** 최근 N일 AI 판정 품질 */
    @GetMapping("/quality")
    public AiQualityDto quality(@RequestParam(defaultValue = "7") int days) {
        return aiQualityService.getQuality(days);
    }

    /** 재학습용 오탐 데이터 (CSV 다운로드) */
    @GetMapping("/false-positives.csv")
    public ResponseEntity<byte[]> exportFalsePositives(@RequestParam(defaultValue = "30") int days) {
        byte[] body = aiQualityService.exportFalsePositivesCsv(days).getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"false_positives_" + LocalDate.now() + ".csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(body);
    }
}
