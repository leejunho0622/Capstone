package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "flow_flags")
@Getter
public class FlowFlags {

    @Id
    private Long flowId;

    private Integer synCount;
    private Integer ackCount;
}