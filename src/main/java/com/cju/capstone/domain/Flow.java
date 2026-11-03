package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * flows : 연결(트래픽) 1건. Suricata flow 이벤트를 collector.py 가 적재.
 * 백엔드는 읽기 전용으로만 사용한다.
 */
@Entity
@Table(name = "flows")
@Getter
public class Flow {

    @Id
    private Long id;

    /** Suricata 업무 키 (다른 테이블은 이 값으로 연결) */
    @Column(name = "flow_id", nullable = false, unique = true)
    private Long flowId;

    @Column(name = "start_time")
    private LocalDateTime startTime;

    @Column(name = "end_time")
    private LocalDateTime endTime;

    @Column(name = "src_ip")
    private String srcIp;

    @Column(name = "dest_ip")
    private String destIp;

    @Column(name = "src_port")
    private Integer srcPort;

    @Column(name = "dest_port")
    private Integer destPort;

    private String protocol;

    @Column(name = "bytes_toserver")
    private Long bytesToServer;

    @Column(name = "bytes_toclient")
    private Long bytesToClient;

    @Column(name = "pkts_toserver")
    private Integer pktsToServer;

    @Column(name = "pkts_toclient")
    private Integer pktsToClient;

    /** Suricata 자체 심각도 (1이 가장 심각) */
    private Integer severity;

    @Column(name = "event_type")
    private String eventType;

    @Column(name = "ids_rule_id")
    private String idsRuleId;

    /** 소속 공격 (attack_events.id), 정상 트래픽은 null */
    @Column(name = "attack_id")
    private Long attackId;
}
