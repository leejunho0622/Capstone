package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

/**
 * flow_flags : 플로우별 TCP 플래그 개수. PK = flows.flow_id
 * (이전 코드의 @MapsId 는 flows.id 와 연결되어 값이 어긋날 수 있어 제거)
 */
@Entity
@Table(name = "flow_flags")
@Getter
public class FlowFlags {

    @Id
    @Column(name = "flow_id")
    private Long flowId;

    @Column(name = "syn_count")
    private int synCount;

    @Column(name = "ack_count")
    private int ackCount;

    @Column(name = "fin_count")
    private int finCount;

    @Column(name = "rst_count")
    private int rstCount;

    @Column(name = "psh_count")
    private int pshCount;

    @Column(name = "urg_count")
    private int urgCount;
}
