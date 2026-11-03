package com.cju.capstone.service;

import com.cju.capstone.config.AttackType;
import com.cju.capstone.config.SchemaCheck;
import com.cju.capstone.domain.AiResult;
import com.cju.capstone.dto.AiQualityDto;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.AttackEventRepository;
import com.cju.capstone.repository.IncidentTriageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AiQualityService {

    private static final int MAX_DAYS = 90;
    private static final int MAX_EXPORT_ROWS = 20_000;
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final AiResultRepository aiResultRepository;
    private final AttackEventRepository attackEventRepository;
    private final IncidentTriageRepository triageRepository;
    private final SchemaCheck schemaCheck;

    public AiQualityDto getQuality(int days) {
        int d = Math.min(MAX_DAYS, Math.max(1, days));
        LocalDateTime since = LocalDate.now().minusDays(d - 1L).atStartOfDay();

        // ---- 모델 지표 (ai_results) ----
        Map<String, Object[]> byType = new HashMap<>();
        long analyzed = 0, attackFlows = 0, fpFlows = 0;
        double confWeighted = 0;
        for (Object[] r : aiResultRepository.qualityByType(since)) {
            String type = String.valueOf(r[0]);
            long count = num(r[1]).longValue();
            double conf = num(r[2]).doubleValue();
            long fp = num(r[4]).longValue();
            byType.put(type, r);
            analyzed += count;
            fpFlows += fp;
            if (!"Normal".equals(type)) {
                attackFlows += count;
                confWeighted += conf * count;
            }
        }

        // ---- 사람 지표 (incident_triage × attack_events) ----
        Map<String, Long> incidents = new HashMap<>();
        for (Object[] r : attackEventRepository.countByTypeSince(since)) {
            incidents.put(String.valueOf(r[0]), num(r[1]).longValue());
        }
        Map<String, Map<String, Long>> outcome = new HashMap<>();
        List<Object[]> outcomeRows = schemaCheck.triageAvailable() ? triageRepository.outcomeByType(since) : List.of();
        for (Object[] r : outcomeRows) {
            outcome.computeIfAbsent(String.valueOf(r[0]), k -> new HashMap<>())
                    .merge(String.valueOf(r[1]), num(r[2]).longValue(), Long::sum);
        }

        // 7개 유형은 항상 고정 순서로, 그 밖의 유형(예: Normal)은 뒤에
        LinkedHashSet<String> order = new LinkedHashSet<>();
        Arrays.stream(AttackType.values()).forEach(t -> order.add(t.name()));
        order.addAll(new TreeSet<>(byType.keySet()));

        List<AiQualityDto.TypeQuality> types = new ArrayList<>();
        long reviewed = 0, fpIncidents = 0;
        for (String type : order) {
            Object[] r = byType.get(type);
            Map<String, Long> o = outcome.getOrDefault(type, Map.of());
            long total = incidents.getOrDefault(type, 0L);
            long resolved = o.getOrDefault("RESOLVED", 0L);
            long fp = o.getOrDefault("FALSE_POSITIVE", 0L);
            long ack = o.getOrDefault("ACK", 0L);
            if (!"Normal".equals(type)) {
                reviewed += resolved + fp;
                fpIncidents += fp;
            }
            types.add(new AiQualityDto.TypeQuality(
                    type,
                    r == null ? 0 : num(r[1]).longValue(),
                    r == null ? 0 : round(num(r[2]).doubleValue(), 3),
                    r == null ? 0 : round(num(r[3]).doubleValue(), 1),
                    r == null ? 0 : num(r[4]).longValue(),
                    total,
                    resolved,
                    fp,
                    ack,
                    Math.max(0, total - resolved - fp - ack)));
        }

        return new AiQualityDto(
                d,
                analyzed,
                attackFlows,
                attackFlows == 0 ? 0 : round(confWeighted / attackFlows, 3),
                fpFlows,
                reviewed,
                fpIncidents,
                types,
                histogram(aiResultRepository.confidenceHistogram(since), 0.1),
                histogram(aiResultRepository.riskHistogram(since), 10),
                aiResultRepository.modelUsage(since).stream()
                        .map(r -> new AiQualityDto.ModelUsage(
                                r[0] == null ? "-" : r[0].toString(),
                                r[1] == null ? "-" : r[1].toString(),
                                num(r[2]).longValue()))
                        .toList());
    }

    /**
     * 재학습용 오탐 데이터 CSV
     * 관제요원이 오탐으로 처리한 경보의 플로우 → ai_results.is_false_positive = true 인 행
     * feature_vector(모델 입력 14개 특징값)를 그대로 담아, trainer.py 에서 Normal 라벨로 보정해 재학습할 수 있다.
     */
    public String exportFalsePositivesCsv(int days) {
        int d = Math.min(MAX_DAYS * 4, Math.max(1, days));
        LocalDateTime since = LocalDate.now().minusDays(d - 1L).atStartOfDay();
        List<AiResult> rows = aiResultRepository
                .findByFalsePositiveTrueAndAnalyzedAtGreaterThanEqualOrderByAnalyzedAtDesc(
                        since, PageRequest.of(0, MAX_EXPORT_ROWS));

        StringBuilder sb = new StringBuilder("﻿"); // 엑셀 한글 깨짐 방지 BOM
        sb.append("flow_id,analyzed_at,model_name,model_version,predicted_type,predicted_subtype,")
                .append("confidence,risk_score,corrected_label,feature_vector\r\n");
        for (AiResult a : rows) {
            sb.append(a.getFlowId()).append(',')
                    .append(a.getAnalyzedAt() == null ? "" : a.getAnalyzedAt().format(TS)).append(',')
                    .append(csv(a.getModelName())).append(',')
                    .append(csv(a.getModelVersion())).append(',')
                    .append(csv(a.getAttackType())).append(',')
                    .append(csv(a.getAttackSubtype())).append(',')
                    .append(a.getConfidence() == null ? "" : a.getConfidence()).append(',')
                    .append(a.getRiskScore() == null ? "" : a.getRiskScore()).append(',')
                    .append("Normal").append(',')
                    .append(csv(a.getFeatureVector())).append("\r\n");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------

    private static List<AiQualityDto.Bucket> histogram(List<Object[]> rows, double width) {
        long[] counts = new long[10];
        for (Object[] r : rows) {
            int b = num(r[0]).intValue();
            if (b >= 0 && b < 10) {
                counts[b] += num(r[1]).longValue();
            }
        }
        List<AiQualityDto.Bucket> out = new ArrayList<>(10);
        for (int i = 0; i < 10; i++) {
            out.add(new AiQualityDto.Bucket(round(i * width, 2), round((i + 1) * width, 2), counts[i]));
        }
        return out;
    }

    private static Number num(Object o) {
        return o instanceof Number n ? n : 0;
    }

    private static double round(double v, int digits) {
        double f = Math.pow(10, digits);
        return Math.round(v * f) / f;
    }

    private static String csv(String s) {
        if (s == null) {
            return "";
        }
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }
}
