"""
Tier 2: LLM 기반 분석기 (Ollama + Gemma)

역할을 두 가지로 명확히 분리한다.
1) SUMMARIZE : 규칙 엔진이 이미 확정 판정한 건에 대해, 사람이 읽을 자연어 요약/심각도만 생성.
               (공격 여부 판단을 다시 LLM에 맡기지 않음 -> 일관성 유지, 불필요한 LLM 의존 제거)
2) CLASSIFY  : 규칙 엔진이 확신하지 못한(needs_llm=True) 애매한 로그에 대해서만
               실제 분류 판단을 LLM에 위임.

이렇게 나누는 이유: 신입 포트폴리오에서 "왜 LLM을 여기 뒀는가"라는 질문에
"규칙으로 처리 가능한 건 규칙으로, 규칙이 놓치는 회색지대만 LLM으로" 라고
답할 수 있어야 하고, 실제 코드도 그 구조를 반영해야 하기 때문.
"""
import json
import logging
import requests

import config

logger = logging.getLogger("ai_analyzer")


def _call_ollama(prompt: str) -> str:
    # 어떤 형태의 URL이 들어와도 /api/generate 경로가 정확히 한 번만 붙도록 처리
    base_url = config.OLLAMA_URL.split("/api")[0].rstrip("/")
    url = f"{base_url}/api/generate"
    
    payload = {
        "model": config.MODEL_NAME,  # 'gemma2:2b'
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 1024,
            "num_predict": 128,
            "temperature": 0.0,
        },
    }
    try:
        resp = requests.post(url, json=payload, timeout=config.LLM_TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.Timeout:
        logger.warning("Ollama 응답 타임아웃")
        return ""
    except Exception as e:
        logger.warning(f"Ollama 호출 실패: {e}")
        return ""


def summarize_confirmed(log_message: str, attack_type: str, reason: str) -> dict:
    """규칙 엔진이 이미 확정한 탐지 결과를 사람이 읽을 요약으로 변환."""
    prompt = f"""다음은 보안 관제 시스템이 이미 '{attack_type}' 공격으로 확정 판정한 로그다.
로그: {log_message}
판정 근거: {reason}

이 내용을 보안 담당자가 바로 읽을 수 있도록 한국어 한 문장으로 요약하고, 심각도를 판단하라.
반드시 아래 형식으로만 답하라:
심각도: [낮음/중간/높음/치명적]
요약: [한 줄 요약]"""

    raw = _call_ollama(prompt)
    severity, summary = _parse_severity_summary(raw)
    if not summary:
        summary = f"{attack_type} 공격 패턴 확인됨 ({reason})"
    if not severity:
        severity = "높음" if attack_type in ("Brute Force", "SQLi") else "중간"
    return {"severity": severity, "summary": summary, "raw": raw}


def classify_ambiguous(log_message: str) -> dict:
    """규칙 엔진이 확신하지 못한 로그를 LLM이 직접 분류."""
    prompt = f"""아래 웹 서버 로그가 공격 시도인지 판단하라. 알려진 정상 트래픽과 혼동하지 않도록 신중히 보라.
로그: {log_message}

가능한 공격유형: Brute Force, SQLi, XSS, Normal
반드시 아래 형식으로만 답하라:
위험여부: [위험/안전]
공격유형: [Brute Force/SQLi/XSS/Normal]
심각도: [낮음/중간/높음/치명적]
요약: [한 줄 요약, 판단 근거 포함]"""

    raw = _call_ollama(prompt)
    is_danger, attack_type, severity, summary = _parse_full_response(raw)
    return {
        "is_danger": is_danger,
        "attack_type": attack_type,
        "severity": severity or "낮음",
        "summary": summary or "LLM 응답 파싱 실패 (원문 확인 필요)",
        "raw": raw,
    }


def _parse_severity_summary(text: str):
    severity, summary = "", ""
    for line in text.split("\n"):
        if "심각도" in line:
            severity = line.split(":", 1)[-1].strip()
        elif "요약" in line:
            summary = line.split(":", 1)[-1].strip()
    return severity, summary


def _parse_full_response(text: str):
    is_danger, attack_type, severity, summary = "안전", "Normal", "", ""
    for line in text.split("\n"):
        if "위험여부" in line:
            is_danger = "위험" if "위험" in line.split(":", 1)[-1] else "안전"
        elif "공격유형" in line:
            attack_type = line.split(":", 1)[-1].strip()
        elif "심각도" in line:
            severity = line.split(":", 1)[-1].strip()
        elif "요약" in line:
            summary = line.split(":", 1)[-1].strip()
    return is_danger, attack_type, severity, summary
