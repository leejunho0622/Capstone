package com.cju.capstone.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "ai_results")
@Getter
@Setter
public class AiResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String modelName;
    private String prediction;
    private String attackType;

    private Double confidence;
    private Double riskScore;

    private String action;

    @Column(columnDefinition = "TEXT")
    private String actionDetail;

    private LocalDateTime analyzedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "flow_id", referencedColumnName = "flow_id")
    private Flow flow;
}