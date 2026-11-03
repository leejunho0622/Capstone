package com.cju.capstone.service;

import com.cju.capstone.config.AttackType;
import com.cju.capstone.config.SchemaCheck;
import com.cju.capstone.domain.AiResult;
import com.cju.capstone.domain.AttackEvent;
import com.cju.capstone.domain.Flow;
import com.cju.capstone.domain.FlowFlags;
import com.cju.capstone.domain.IncidentTriage;
import com.cju.capstone.dto.DetectionDto;
import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.dto.IncidentDto;
import com.cju.capstone.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 탐지 성능
 * 1) IDS 룰 대비 AI: 같은 트래픽을 Suricata 룰과 AI 가 각각 공격으로 봤는지 비교
 * 2) 탐지 지연: 공격 시작 → 첫 판정(MTTD), 연결 종료 → 분석
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DetectionService {

    private static final int MAX_DAYS = 90;
    private static final int SAMPLE_LIMIT = 10;
    private static final int LATENCY_LIMIT = 20_000;
    /** 이 범위를 벗어나는 지연은 실시간 탐지로 볼 수 없어 제외 (합성 데이터·시간대 불일치) */
    private static final long MAX_PLAUSIBLE_SEC = 3600;
    private static final long MIN_PLAUSIBLE_SEC = -60;

    private static final long[][] BUCKETS = {
            {Long.MIN_VALUE, 5}, {5, 10}, {10, 30}, {30, 60}, {60, 120}, {120, 300}, {300, Long.MAX_VALUE}};
    private static final String[] BUCKET_LABELS = {"5초 미만", "5~10초", "10~30초", "30~60초", "1~2분", "2~5분", "5분 이상"};

    private final DetectionStatsRepository statsRepository;
    private final AttackEventRepository attackEventRepository;
    private final FlowRepository flowRepository;
    private final FlowFlagsRepository flowFlagsRepository;
    private final AiResultRepository aiResultRepository;
    private final IncidentTriageRepository triageRepository;
    private final SchemaCheck schemaCheck;

    // ======================================================================
    // 1) IDS 룰 대비 AI
    // ======================================================================

    public DetectionDto.IdsComparison idsComparison(int days) {
        LocalDateTime since = since(days);

        long both = 0, aiOnly = 0, idsOnly = 0, neither = 0;
        for (Object[] r : statsRepository.flowMatrix(since)) {
            boolean ids = num(r[0]).intValue() == 1;
            boolean ai = num(r[1]).intValue() == 1;
            long n = num(r[2]).longValue();
            if (ids && ai) both += n;
            else if (ai) aiOnly += n;
            else if (ids) idsOnly += n;
            else neither += n;
        }

        Map<String, long[]> flowsByType = new HashMap<>();
        for (Object[] r : statsRepository.flowsByType(since)) {
            flowsByType.put(String.valueOf(r[0]), new long[]{num(r[1]).longValue(), num(r[2]).longValue()});
        }
        Map<String, long[]> incByType = new HashMap<>();
        long incTotal = 0, incIds = 0;
        for (Object[] r : statsRepository.incidentsByType(since)) {
            long total = num(r[1]).longValue();
            long ids = num(r[2]).longValue();
            incByType.put(String.valueOf(r[0]), new long[]{total, ids});
            incTotal += total;
            incIds += ids;
        }

        LinkedHashSet<String> order = new LinkedHashSet<>();
        Arrays.stream(AttackType.values()).forEach(t -> order.add(t.name()));
        order.addAll(new TreeSet<>(flowsByType.keySet()));
        order.addAll(new TreeSet<>(incByType.keySet()));
        List<DetectionDto.TypeRow> types = new ArrayList<>();
        for (String t : order) {
            long[] f = flowsByType.getOrDefault(t, new long[]{0, 0});
            long[] i = incByType.getOrDefault(t, new long[]{0, 0});
            types.add(new DetectionDto.TypeRow(t, f[0], f[1], i[0], i[1]));
        }

        return new DetectionDto.IdsComparison(
                clampDays(days),
                new DetectionDto.FlowMatrix(both, aiOnly, idsOnly, neither),
                new DetectionDto.IncidentSummary(incTotal, incIds, incTotal - incIds),
                types,
                aiOnlyIncidents(statsRepository.aiOnlyIncidentIds(since, SAMPLE_LIMIT)),
                flowsById(statsRepository.idsOnlyFlowIds(since, SAMPLE_LIMIT)));
    }

    private List<IncidentDto> aiOnlyIncidents(List<Number> ids) {
        List<Long> idList = ids.stream().map(Number::longValue).toList();
        if (idList.isEmpty()) {
            return List.of();
        }
        Map<Long, AttackEvent> events = attackEventRepository.findAllById(idList).stream()
                .collect(Collectors.toMap(AttackEvent::getId, Function.identity()));
        Map<Long, IncidentTriage> triage = schemaCheck.triageAvailable()
                ? triageRepository.findAllByAttackIdIn(idList).stream()
                .collect(Collectors.toMap(IncidentTriage::getAttackId, Function.identity()))
                : Map.of();
        // 쿼리의 정렬(위험도 순)을 유지
        return idList.stream()
                .filter(events::containsKey)
                .map(id -> IncidentDto.of(events.get(id), triage.get(id)))
                .toList();
    }

    private List<FlowDto> flowsById(List<Number> ids) {
        List<Long> idList = ids.stream().map(Number::longValue).toList();
        if (idList.isEmpty()) {
            return List.of();
        }
        Map<Long, Flow> flows = flowRepository.findAllByFlowIdIn(idList).stream()
                .collect(Collectors.toMap(Flow::getFlowId, Function.identity(), (a, b) -> a));
        Map<Long, FlowFlags> flags = flowFlagsRepository.findAllByFlowIdIn(idList).stream()
                .collect(Collectors.toMap(FlowFlags::getFlowId, Function.identity(), (a, b) -> a));
        Map<Long, AiResult> ai = aiResultRepository.findAllByFlowIdIn(idList).stream()
                .collect(Collectors.toMap(AiResult::getFlowId, Function.identity(), (a, b) -> a));
        return idList.stream()
                .filter(flows::containsKey)
                .map(id -> FlowDto.of(flows.get(id), flags.get(id), ai.get(id)))
                .toList();
    }

    // ======================================================================
    // 2) 탐지 지연
    // ======================================================================

    public DetectionDto.Latency latency(int days) {
        LocalDateTime since = since(days);
        return new DetectionDto.Latency(
                clampDays(days),
                stats(statsRepository.incidentLatencySeconds(since)),
                stats(statsRepository.flowLatencySeconds(since, LATENCY_LIMIT)));
    }

    private static DetectionDto.LatencyStats stats(List<Number> raw) {
        List<Long> valid = new ArrayList<>();
        long excluded = 0;
        for (Number n : raw) {
            if (n == null) {
                excluded++;
                continue;
            }
            long v = n.longValue();
            if (v < MIN_PLAUSIBLE_SEC || v > MAX_PLAUSIBLE_SEC) {
                excluded++;
            } else {
                valid.add(Math.max(0, v));
            }
        }
        Collections.sort(valid);

        long[] counts = new long[BUCKETS.length];
        double sum = 0;
        for (long v : valid) {
            sum += v;
            for (int i = 0; i < BUCKETS.length; i++) {
                if (v >= BUCKETS[i][0] && v < BUCKETS[i][1]) {
                    counts[i]++;
                    break;
                }
            }
        }
        List<DetectionDto.Bucket> buckets = new ArrayList<>();
        for (int i = 0; i < BUCKETS.length; i++) {
            buckets.add(new DetectionDto.Bucket(BUCKET_LABELS[i],
                    Math.max(0, BUCKETS[i][0]), BUCKETS[i][1] == Long.MAX_VALUE ? -1 : BUCKETS[i][1], counts[i]));
        }
        return new DetectionDto.LatencyStats(
                valid.size(),
                excluded,
                valid.isEmpty() ? 0 : round1(sum / valid.size()),
                percentile(valid, 0.50),
                percentile(valid, 0.90),
                percentile(valid, 0.95),
                valid.isEmpty() ? 0 : valid.get(valid.size() - 1),
                buckets);
    }

    /** 최근접 순위 방식 백분위 */
    private static double percentile(List<Long> sorted, double p) {
        if (sorted.isEmpty()) {
            return 0;
        }
        int idx = (int) Math.ceil(p * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, idx)));
    }

    // ----------------------------------------------------------------------

    private static int clampDays(int days) {
        return Math.min(MAX_DAYS, Math.max(1, days));
    }

    private static LocalDateTime since(int days) {
        return LocalDate.now().minusDays(clampDays(days) - 1L).atStartOfDay();
    }

    private static Number num(Object o) {
        return o instanceof Number n ? n : 0;
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }
}
