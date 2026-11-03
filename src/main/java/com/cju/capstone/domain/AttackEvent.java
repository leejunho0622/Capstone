package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * attack_events : 공격 1건 (여러 플로우를 attack_grouper.py 가 묶은 단위)
 * 관제 화면의 '경보(Incident)' 단위로 사용한다.
 */
@Entity
@Table(name = "attack_events")
@Getter
public class AttackEvent {

    @Id
    private Long id;

    @Column(name = "attack_type", nullable = false)
    private String attackType;

    @Column(name = "attack_subtype")
    private String attackSubtype;

    /** 묶음 기준. src:<IP> 또는 dst:<IP>(DDoS/SYNFlood) */
    @Column(name = "group_key", nullable = false)
    private String groupKey;

    @Column(name = "src_ip")
    private String srcIp;

    @Column(name = "dest_ip")
    private String destIp;

    @Column(name = "dest_port")
    private Integer destPort;

    @Column(name = "unique_src_ips")
    private Integer uniqueSrcIps;

    @Column(name = "unique_dst_ips")
    private Integer uniqueDstIps;

    @Column(name = "unique_dst_ports")
    private Integer uniqueDstPorts;

    @Column(name = "first_seen", nullable = false)
    private LocalDateTime firstSeen;

    @Column(name = "last_seen", nullable = false)
    private LocalDateTime lastSeen;

    @Column(name = "flow_count")
    private Integer flowCount;

    @Column(name = "max_risk")
    private Double maxRisk;

    @Column(name = "avg_risk")
    private Double avgRisk;

    /** 공격 단위 종합 위험도 = 0.7*max + 0.2*avg + 규모 보너스(최대 10) */
    @Column(name = "event_risk")
    private Double eventRisk;

    private String action;

    @Column(name = "action_detail", columnDefinition = "TEXT")
    private String actionDetail;

    @Column(name = "response_guide", columnDefinition = "JSON")
    private String responseGuide;

    /** open = 진행 중 / closed = 종료 (파이프라인이 관리) */
    @Column(name = "status")
    private String state;
}
