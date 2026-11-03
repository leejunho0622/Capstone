package com.cju.capstone.service;

import com.cju.capstone.config.AttackType;
import com.cju.capstone.dto.AttackTypeDto;
import com.cju.capstone.dto.DashboardSummaryDto;
import com.cju.capstone.dto.RealtimeDto;
import com.cju.capstone.dto.TimelineDto;
import com.cju.capstone.repository.AttackEventRepository;
import com.cju.capstone.repository.FlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * 대시보드 집계
 * - '공격 건수'는 모두 attack_events(공격 단위) 기준
 *   (이전: flows×ai_results 를 출발지·유형·분 단위로 GROUP BY 해 공격 수를 '추정' → 이제 파이프라인이 묶은 값을 그대로 사용)
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DashboardService {

    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("MM/dd");
    /** 진행 중 공격 중 이 시간 안에 활동이 있으면 '실시간 공격 중' (attack_grouper 의 묶음 간격 120초와 맞춤) */
    private static final long REALTIME_WINDOW_SECONDS = 120;
    private static final String OPEN = "open";

    private final FlowRepository flowRepository;
    private final AttackEventRepository attackEventRepository;

    public DashboardSummaryDto getSummary() {
        LocalDateTime today = LocalDate.now().atStartOfDay();
        return new DashboardSummaryDto(
                flowRepository.count(),
                flowRepository.countByStartTimeGreaterThanEqual(today),
                attackEventRepository.countByFirstSeenGreaterThanEqual(today),
                attackEventRepository.countByState(OPEN),
                attackEventRepository.existsByStateAndLastSeenGreaterThanEqual(
                        OPEN, LocalDateTime.now().minusSeconds(REALTIME_WINDOW_SECONDS)),
                round1(attackEventRepository.averageEventRiskSince(today)),
                round1(attackEventRepository.maxEventRiskSince(today))
        );
    }

    /** 유형별 공격 건수. 범례 색이 고정되도록 7종 모두 enum 순서로 반환 (없는 유형은 0) */
    public List<AttackTypeDto> getAttackTypes(String period) {
        LocalDateTime since = "today".equalsIgnoreCase(period)
                ? LocalDate.now().atStartOfDay()
                : LocalDateTime.of(1970, 1, 1, 0, 0);

        Map<String, Long> counts = new HashMap<>();
        for (Object[] row : attackEventRepository.countByTypeSince(since)) {
            counts.merge(String.valueOf(row[0]), ((Number) row[1]).longValue(), Long::sum);
        }

        List<AttackTypeDto> result = new ArrayList<>();
        for (AttackType type : AttackType.values()) {
            result.add(new AttackTypeDto(type.name(), counts.getOrDefault(type.name(), 0L)));
        }
        // enum 에 없는 새 유형이 들어와도 버리지 않고 뒤에 붙임
        counts.keySet().stream()
                .filter(k -> Arrays.stream(AttackType.values()).noneMatch(t -> t.name().equals(k)))
                .filter(k -> !"Normal".equals(k))
                .sorted()
                .forEach(k -> result.add(new AttackTypeDto(k, counts.get(k))));
        return result;
    }

    /** 최근 7일(오늘 포함) 일별 공격 건수, 빈 날은 0 */
    public List<TimelineDto> getTimeline() {
        LocalDate first = LocalDate.now().minusDays(6);
        long[] buckets = new long[7];
        for (LocalDateTime t : attackEventRepository.findFirstSeenSince(first.atStartOfDay())) {
            int idx = (int) ChronoUnit.DAYS.between(first, t.toLocalDate());
            if (idx >= 0 && idx < 7) {
                buckets[idx]++;
            }
        }
        List<TimelineDto> result = new ArrayList<>(7);
        for (int i = 0; i < 7; i++) {
            result.add(new TimelineDto(first.plusDays(i).format(DAY), buckets[i]));
        }
        return result;
    }

    /** 최근 24시간 시간대별 공격 건수 (0~23시). 프론트가 현재 시각 기준으로 회전해서 그림 */
    public List<RealtimeDto> getRealtime() {
        // 현재 시각의 정각 기준 23시간 전부터 → 같은 '시' 가 어제/오늘 겹치지 않음
        LocalDateTime since = LocalDateTime.now().truncatedTo(ChronoUnit.HOURS).minusHours(23);
        long[] buckets = new long[24];
        for (LocalDateTime t : attackEventRepository.findFirstSeenSince(since)) {
            buckets[t.getHour()]++;
        }
        List<RealtimeDto> result = new ArrayList<>(24);
        for (int h = 0; h < 24; h++) {
            result.add(new RealtimeDto(h, buckets[h]));
        }
        return result;
    }

    private static double round1(Double v) {
        return v == null ? 0.0 : Math.round(v * 10.0) / 10.0;
    }
}
