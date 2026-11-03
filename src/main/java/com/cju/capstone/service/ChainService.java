package com.cju.capstone.service;

import com.cju.capstone.config.KillChainStage;
import com.cju.capstone.domain.AttackEvent;
import com.cju.capstone.dto.ChainDto;
import com.cju.capstone.repository.AttackEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 공격 연관 분석
 *
 * 1) 기간 안에 활동한 공격(attack_events)을 대표 출발지(src_ip) 기준으로 모은다.
 * 2) 시간순으로 보며, 직전 공격이 끝난 뒤 gap 분 이상 비면 다른 체인으로 나눈다.
 * 3) 각 공격을 킬체인 단계(정찰→침투 시도→장악→영향)로 바꿔, 앞 단계 뒤에
 *    더 진행된 단계가 나오면 escalated = true.
 * 4) 체인 위험도 = min(100, 최대 공격 위험도 + 8×(거친 단계 수-1) + (진행 시 5))
 *    → 같은 점수의 단발 공격보다 '정찰 후 침투'처럼 이어진 공격을 더 위험하게 본다.
 *
 * AI 파이프라인(attack_grouper.py)은 '같은 유형'만 묶으므로, 유형이 바뀌며 이어지는
 * 공격 흐름은 이 단계에서 처음으로 보인다.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ChainService {

    private static final int MAX_HOURS = 24 * 30;
    private static final DateTimeFormatter ID_TIME = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final AttackEventRepository attackEventRepository;

    public List<ChainDto> findChains(int hours, int gapMinutes, int minEvents) {
        int h = Math.min(MAX_HOURS, Math.max(1, hours));
        Duration gap = Duration.ofMinutes(Math.min(24 * 60, Math.max(1, gapMinutes)));
        int min = Math.max(1, minEvents);

        List<AttackEvent> events = attackEventRepository
                .findByLastSeenGreaterThanEqualOrderByFirstSeenAsc(LocalDateTime.now().minusHours(h));

        // 출발지별로 모으기 (출발지가 없는 행은 제외)
        Map<String, List<AttackEvent>> bySrc = new LinkedHashMap<>();
        for (AttackEvent e : events) {
            if (e.getSrcIp() == null || e.getSrcIp().isBlank() || e.getFirstSeen() == null) {
                continue;
            }
            bySrc.computeIfAbsent(e.getSrcIp(), k -> new ArrayList<>()).add(e);
        }

        List<ChainDto> chains = new ArrayList<>();
        for (List<AttackEvent> list : bySrc.values()) {
            List<AttackEvent> current = new ArrayList<>();
            LocalDateTime currentEnd = null;
            for (AttackEvent e : list) {
                if (currentEnd != null && e.getFirstSeen().isAfter(currentEnd.plus(gap))) {
                    addIfLongEnough(chains, current, min);
                    current = new ArrayList<>();
                    currentEnd = null;
                }
                current.add(e);
                LocalDateTime end = e.getLastSeen() != null ? e.getLastSeen() : e.getFirstSeen();
                currentEnd = currentEnd == null || end.isAfter(currentEnd) ? end : currentEnd;
            }
            addIfLongEnough(chains, current, min);
        }

        // 위험한 체인 → 최근 체인 순
        chains.sort(Comparator.comparingDouble(ChainDto::chainRisk).reversed()
                .thenComparing(ChainDto::lastSeen, Comparator.reverseOrder()));
        return chains;
    }

    private static void addIfLongEnough(List<ChainDto> out, List<AttackEvent> group, int minEvents) {
        if (group.size() >= minEvents) {
            out.add(toDto(group));
        }
    }

    private static ChainDto toDto(List<AttackEvent> group) {
        LocalDateTime first = group.get(0).getFirstSeen();
        LocalDateTime last = group.stream()
                .map(e -> e.getLastSeen() != null ? e.getLastSeen() : e.getFirstSeen())
                .max(Comparator.naturalOrder()).orElse(first);

        // 단계: 시간순으로 처음 등장한 순서대로
        LinkedHashSet<KillChainStage> stages = new LinkedHashSet<>();
        boolean escalated = false;
        int maxOrderSoFar = -1;
        for (AttackEvent e : group) {
            KillChainStage s = KillChainStage.of(e.getAttackType());
            stages.add(s);
            if (s != KillChainStage.ANOMALY) {
                if (maxOrderSoFar >= 1 && s.order() > maxOrderSoFar) {
                    escalated = true;
                }
                maxOrderSoFar = Math.max(maxOrderSoFar, s.order());
            }
        }
        KillChainStage highest = stages.stream()
                .max(Comparator.comparingInt(KillChainStage::order))
                .orElse(KillChainStage.ANOMALY);

        LinkedHashSet<String> targets = new LinkedHashSet<>();
        long flows = 0;
        double maxRisk = 0;
        boolean active = false;
        List<ChainDto.ChainEventDto> items = new ArrayList<>();
        for (AttackEvent e : group) {
            if (e.getDestIp() != null) {
                targets.add(e.getDestIp());
            }
            flows += e.getFlowCount() != null ? e.getFlowCount() : 0;
            double risk = e.getEventRisk() != null ? e.getEventRisk() : 0.0;
            maxRisk = Math.max(maxRisk, risk);
            active |= "open".equalsIgnoreCase(e.getState());
            items.add(new ChainDto.ChainEventDto(
                    e.getId(), e.getAttackType(), e.getAttackSubtype(),
                    KillChainStage.of(e.getAttackType()).name(),
                    e.getFirstSeen(), e.getLastSeen(), e.getDestIp(), e.getDestPort(),
                    e.getFlowCount() != null ? e.getFlowCount() : 0, round1(risk), e.getState()));
        }

        long realStages = stages.stream().filter(s -> s != KillChainStage.ANOMALY).count();
        double chainRisk = Math.min(100.0,
                maxRisk + 8.0 * Math.max(0, realStages - 1) + (escalated ? 5.0 : 0.0));

        String srcIp = group.get(0).getSrcIp();
        return new ChainDto(
                srcIp + "@" + first.format(ID_TIME),
                srcIp,
                first,
                last,
                group.size(),
                flows,
                targets.size(),
                targets.stream().limit(5).toList(),
                stages.stream().map(Enum::name).toList(),
                highest.name(),
                escalated,
                active,
                round1(maxRisk),
                round1(chainRisk),
                items);
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }
}
