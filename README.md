# 🛡️ AI-Powered Security SIEM & Threat Detection Pipeline

> **리눅스 시스템/웹 로그 실시간 수집, 룰 기반 1차 필터링, 로컬 LLM(Gemma 2) 기반 2차 위협 분석을 결합한 하이브리드 SIEM 파이프라인**

---

## 📌 1. 프로젝트 개요 (Overview)
본 프로젝트는 보안 관제 및 인프라 엔지니어링 역량을 강화하기 위해 구축한 **실시간 보안 로그 수집 및 지능형 위협 탐지 시스템**입니다. 
단순한 시그니처 룰 매칭의 한계(오탐 및 변형 공격 대응 취약)를 극복하기 위해, **Tier 1(규칙 엔진)과 Tier 2(로컬 LLM)**를 결합한 하이브리드 아키텍처를 설계하여 오탐을 줄이고 실시간성을 확보했습니다.

---

## 🏗️ 2. 시스템 아키텍처 (Architecture)

```text
[Remote Linux Server]
  ├── /var/log/auth.log ──┐
  └── /var/log/nginx/access.log ──┴─> [Multi-threaded Python Collector (Paramiko)]
                                             │
                                             ▼
                                    [Tier 1: Rule Engine]
                                             │
                       ┌─────────────────────┼─────────────────────┐
                       ▼                     ▼                     ▼
                  (Confirmed)           (Suspicious)            (Normal)
                       │                     │                     │
                       ▼                     ▼                     ▼
              [LLM Summary / Severity]  [Tier 2: Local LLM]       [Discard]
                       │                     │                (Noise Drop)
                       └─────────────────────┴─────────────────────┘
                                             │
                                             ▼
                                 [Elasticsearch Indexing]
                                             │
                                             ▼
                                   [Kibana Visualization]