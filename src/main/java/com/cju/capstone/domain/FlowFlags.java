package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
@Table(name = "flow_flags")
public class FlowFlags {

    @Id
    private Long flowId;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "flow_id")
    private Flow flow;

    private int synCount;
    private int ackCount;
    private int finCount;
    private int rstCount;
    private int pshCount;
    private int urgCount;
}