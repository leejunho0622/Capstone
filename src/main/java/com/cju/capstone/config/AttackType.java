package com.cju.capstone.config;

/**
 * AI 파이프라인(inference.py)이 판정하는 공격 유형.
 * 차트 범례·색이 고정되도록 이 순서대로 항상 내려준다.
 */
public enum AttackType {
    BruteForce,
    PortScan,
    NetworkScan,
    DDoS,
    SYNFlood,
    C2Beacon,
    UnknownAnomaly
}
