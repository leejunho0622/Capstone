# 관제탑 — AI 기반 네트워크 침입 탐지 관제 대시보드

Suricata + AI(IF·RF·시퀀스) 파이프라인이 MySQL(`ids_db`)에 적재한 데이터를
실시간 보안 관제(SOC) 화면으로 보여주는 웹 애플리케이션입니다.

```
Suricata → collector.py → inference.py → attack_grouper.py → MySQL(ids_db)
                                                               │
                                     Spring Boot (8080) ◀──────┘
                                           │  /api/*
                                     React + Vite (5173)
```

## 실행 순서

### 1. DB 준비 (최초 1회)

AI 파이프라인 스키마(flows, flow_flags, ai_results, attack_events)가 만들어진 상태에서
대시보드 전용 테이블·인덱스를 추가합니다.

```bash
mysql -u ids_user -p ids_db < db/schema_dashboard.sql
```

### 2. 백엔드

`src/main/resources/db-local.yml` 에 내 DB 접속 정보를 넣습니다 (Git 에 올라가지 않음).

```yaml
spring:
  datasource:
    url: jdbc:mysql://192.168.0.8:3306/ids_db?serverTimezone=Asia/Seoul&characterEncoding=UTF-8
    username: ids_user
    password: 비밀번호
```

IntelliJ 에서 `Application` 실행, 또는 `./gradlew bootRun`

### 3. 프론트엔드

```bash
cd src/main/frontend
npm install
npm run dev          # http://localhost:5173 (/api 는 8080 으로 프록시)
```

DB·백엔드 없이 화면만 시연할 때:

```bash
npm run mock         # 터미널 1: 목업 API (8080, 실시간으로 공격 생성)
npm run dev          # 터미널 2
```

## API

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/dashboard/summary` | KPI (오늘 공격 수, 진행 중 공격, 위험도 평균/최대 등) |
| GET | `/api/dashboard/attack-types?period=all\|today` | 공격 유형별 건수 (7종 고정 순서) |
| GET | `/api/dashboard/timeline` | 최근 7일 일별 공격 건수 |
| GET | `/api/dashboard/realtime` | 최근 24시간 시간대별 공격 건수 |
| GET | `/api/incidents?hours=24&page=0&size=50` | 경보(공격 단위) 목록, 최근 활동순 |
| GET | `/api/incidents/{id}` | 경보 상세 (대응 가이드 JSON 포함) |
| GET | `/api/incidents/{id}/flows` | 경보에 묶인 플로우 |
| PUT | `/api/incidents/{id}/triage` | 처리 상태 저장 `{status, note, assignee}` |
| GET | `/api/flows?q=&srcIp=&destIp=&port=&protocol=&verdict=&attackType=&hours=` | 트래픽 검색 (최신순) |
| GET | `/api/flows/{flowId}` | 플로우 상세 (위험도 산출 근거 JSON 포함) |
| GET | `/api/flows/{flowId}/ai-results` | 플로우 분석 이력 |
| GET | `/api/chains?hours=24&gap=30&minEvents=2` | 공격 연관 분석: 같은 출발지의 연속 공격을 킬체인 단계(정찰→침투 시도→장악→서비스 공격)로 묶음 |
| GET | `/api/ai/quality?days=7` | AI 판정 품질: 유형별 신뢰도·위험도, 관제요원 확정 정탐/오탐, 분포 |
| GET | `/api/ai/false-positives.csv?days=30` | 재학습용 오탐 데이터 (feature_vector 포함, 보정 라벨 Normal) |
| GET | `/api/ai/ids-comparison?days=7` | IDS 룰(flows.severity) vs AI 판정 교차표·유형별 비교, AI만 탐지한 공격 / 룰만 탐지한 플로우 각 10건 |
| GET | `/api/ai/latency?days=7` | 탐지 지연: 공격 시작→첫 AI 판정(MTTD), 연결 종료→AI 분석 — 평균·p50/p90/p95·구간 분포 (-60초~1시간 밖은 제외) |

- 처리 상태: `NEW`(신규) · `ACK`(확인 중) · `RESOLVED`(조치 완료) · `FALSE_POSITIVE`(오탐)
- 오탐으로 처리하면 소속 플로우의 `ai_results.is_false_positive` 가 true 로 바뀌어 재학습 데이터로 쓸 수 있습니다.

## 공격 체인 위험도

`체인 위험도 = min(100, 최대 공격 위험도 + 8 × (거친 단계 수 − 1) + (앞 단계 → 뒤 단계 진행 시 5))`

AI 파이프라인(attack_grouper.py)은 같은 유형만 묶기 때문에, 유형이 바뀌며 이어지는 공격(예: PortScan → BruteForce → C2Beacon)은
백엔드의 공격 연관 분석에서 처음 하나의 흐름으로 보입니다.

## 위험도 등급 (프론트 `src/lib/severity.ts`)

| 등급 | 종합 위험도 | 근거 |
| --- | --- | --- |
| Critical | 70 이상 | response_playbook 즉시 차단 구간 |
| High | 50 이상 | |
| Medium | 35 이상 | |
| Low | 35 미만 | 정찰성 저위험 |
