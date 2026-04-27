package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "flows")
@Getter
@Setter
public class Flow {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "flow_id", unique = true)
    private Long flowId;

    private String srcIp;
    private String destIp;

    private Integer srcPort;
    private Integer destPort;

    private String protocol;

    private Long bytesToserver;
    private Long bytesToclient;

    private Integer pktsToserver;
    private Integer pktsToclient;

    private LocalDateTime startTime;
    private LocalDateTime endTime;
}