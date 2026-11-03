package com.cju.capstone.service;

import com.cju.capstone.config.SchemaCheck;
import com.cju.capstone.domain.AttackEvent;
import com.cju.capstone.domain.IncidentTriage;
import com.cju.capstone.dto.FlowDto;
import com.cju.capstone.dto.IncidentDto;
import com.cju.capstone.dto.TriageDto;
import com.cju.capstone.dto.TriageRequest;
import com.cju.capstone.repository.AiResultRepository;
import com.cju.capstone.repository.AttackEventRepository;
import com.cju.capstone.repository.IncidentTriageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 경보(Incident) = attack_events 공격 1건
 * - 목록/상세/소속 플로우 조회
 * - 관제요원 처리 상태(incident_triage) 저장
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class IncidentService {

    private static final int MAX_HOURS = 24 * 30;

    private final AttackEventRepository attackEventRepository;
    private final IncidentTriageRepository triageRepository;
    private final AiResultRepository aiResultRepository;
    private final FlowService flowService;
    private final SchemaCheck schemaCheck;

    /** 최근 N시간 안에 활동(last_seen)한 공격, 최근 활동순 */
    public Page<IncidentDto> list(int hours, String attackType, String q, int page, int size) {
        int h = Math.min(MAX_HOURS, Math.max(1, hours));
        String keyword = q == null ? "" : q.trim();
        Page<AttackEvent> events = attackEventRepository.search(
                LocalDateTime.now().minusHours(h),
                attackType == null ? "" : attackType.trim(),
                keyword,
                keyword + "%",
                PageRequest.of(Math.max(0, page), FlowService.clampSize(size),
                        Sort.by(Sort.Direction.DESC, "lastSeen").and(Sort.by(Sort.Direction.DESC, "id"))));

        // 처리 상태는 IN 으로 한 번에 (N+1 방지)
        List<Long> ids = events.getContent().stream().map(AttackEvent::getId).toList();
        Map<Long, IncidentTriage> triage = ids.isEmpty() || !schemaCheck.triageAvailable()
                ? Map.of()
                : triageRepository.findAllByAttackIdIn(ids).stream()
                .collect(Collectors.toMap(IncidentTriage::getAttackId, Function.identity()));

        return events.map(e -> IncidentDto.of(e, triage.get(e.getId())));
    }

    public IncidentDto get(Long id) {
        AttackEvent e = attackEventRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Incident not found: " + id));
        IncidentTriage triage = schemaCheck.triageAvailable() ? triageRepository.findById(id).orElse(null) : null;
        return IncidentDto.of(e, triage);
    }

    public Page<FlowDto> flows(Long id, int page, int size) {
        if (!attackEventRepository.existsById(id)) {
            throw new NotFoundException("Incident not found: " + id);
        }
        return flowService.findByAttack(id, page, size);
    }

    /**
     * 처리 상태 저장 (없으면 생성)
     * 오탐(FALSE_POSITIVE)으로 바꾸면 소속 플로우의 ai_results.is_false_positive = true
     * 오탐에서 다른 상태로 되돌리면 다시 false
     */
    @Transactional
    public TriageDto saveTriage(Long id, TriageRequest req) {
        if (!attackEventRepository.existsById(id)) {
            throw new NotFoundException("Incident not found: " + id);
        }
        if (!schemaCheck.triageAvailable()) {
            throw new TriageUnavailableException();
        }
        IncidentTriage.Status status = parseStatus(req.status());
        IncidentTriage triage = triageRepository.findById(id).orElseGet(() -> new IncidentTriage(id));
        boolean wasFalsePositive = triage.getStatus() == IncidentTriage.Status.FALSE_POSITIVE;

        triage.update(status, limit(req.note(), 2000), limit(req.assignee(), 50));
        IncidentTriage saved = triageRepository.save(triage);

        boolean isFalsePositive = status == IncidentTriage.Status.FALSE_POSITIVE;
        if (isFalsePositive != wasFalsePositive) {
            aiResultRepository.markFalsePositiveByAttackId(id, isFalsePositive);
        }
        return TriageDto.from(saved);
    }

    private static IncidentTriage.Status parseStatus(String raw) {
        try {
            return IncidentTriage.Status.valueOf(raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("status 는 NEW, ACK, RESOLVED, FALSE_POSITIVE 중 하나여야 합니다: " + raw);
        }
    }

    private static String limit(String s, int max) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.length() > max ? t.substring(0, max) : t;
    }
}
