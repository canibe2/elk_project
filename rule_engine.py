"""
Tier 1: 규칙 기반 탐지 엔진

설계 원칙
- LLM 호출 없이 결정적(deterministic)으로 판정 가능한 패턴은 여기서 즉시 처리한다.
- 브루트포스는 단순 키워드 1건 매칭이 아니라, 출발지 IP별로 실패 시도를 누적 카운팅해서
  '짧은 시간에 반복'되는지를 봐야 실제 탐지 로직이라 할 수 있다.
- SQLi/XSS는 페이로드 시그니처 정규식으로 1차 필터링한다.
- 여기서 확신도가 낮게 나오는 경우(패턴이 애매하거나 인코딩된 경우)만 Tier 2(LLM)로 넘긴다.
"""
import re
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional

import config


@dataclass
class Detection:
    is_attack: bool
    attack_type: str          # "Brute Force" | "SQLi" | "XSS" | "Normal"
    confidence: str           # "confirmed" | "suspicious" | "none"
    reason: str
    source_ip: Optional[str] = None
    needs_llm: bool = False   # True면 Tier 2로 넘겨서 추가 판단/요약 필요


# ------------------------------------------------------------------
# 브루트포스: IP별 실패 시도 슬라이딩 윈도우 카운터
# ------------------------------------------------------------------
class BruteForceTracker:
    def __init__(self, threshold: int = None, window_sec: int = None):
        self.threshold = threshold or config.BRUTEFORCE_THRESHOLD
        self.window_sec = window_sec or config.BRUTEFORCE_WINDOW_SEC
        self._attempts = defaultdict(deque)  # ip -> deque[timestamp]

    def register_failure(self, ip: str, ts: float = None) -> int:
        ts = ts or time.time()
        dq = self._attempts[ip]
        dq.append(ts)
        # 윈도우 밖의 오래된 시도는 제거
        while dq and ts - dq[0] > self.window_sec:
            dq.popleft()
        return len(dq)

    def is_over_threshold(self, ip: str) -> bool:
        return len(self._attempts.get(ip, [])) >= self.threshold


_AUTH_FAIL_PATTERN = re.compile(
    r"(failed password|authentication failure|invalid user)", re.IGNORECASE
)
_IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

_bf_tracker = BruteForceTracker()


def check_auth_log(log_message: str) -> Detection:
    """SSH/인증 로그 한 줄을 검사한다."""
    if not _AUTH_FAIL_PATTERN.search(log_message):
        return Detection(False, "Normal", "none", "인증 실패 키워드 없음")

    ip_match = _IP_PATTERN.search(log_message)
    src_ip = ip_match.group(0) if ip_match else "unknown"

    count = _bf_tracker.register_failure(src_ip)

    if count >= _bf_tracker.threshold:
        return Detection(
            is_attack=True,
            attack_type="Brute Force",
            confidence="confirmed",
            reason=f"{src_ip}에서 {_bf_tracker.window_sec}초 내 인증 실패 {count}회 (임계값 {_bf_tracker.threshold}회) 초과",
            source_ip=src_ip,
            needs_llm=False,  # 규칙으로 이미 확정 -> LLM은 요약 생성 용도로만 선택적 호출
        )

    # 임계값 미만이면 아직 공격으로 단정하지 않되, 관찰 대상으로 표시
    return Detection(
        is_attack=False,
        attack_type="Normal",
        confidence="suspicious",
        reason=f"{src_ip} 인증 실패 {count}회 (임계값 미달, 관찰 중)",
        source_ip=src_ip,
        needs_llm=False,
    )


# ------------------------------------------------------------------
# SQLi 시그니처
# ------------------------------------------------------------------
_SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?\d*'?\s*=\s*'?\d*'?", re.IGNORECASE),
    re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r"(--|#)\s*$"),  # SQL 주석으로 뒷부분 무력화 시도
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"%27|%22|%23|%2d%2d"),  # URL 인코딩된 quote/comment
]

# ------------------------------------------------------------------
# XSS 시그니처
# ------------------------------------------------------------------
_XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"on(error|load|mouseover|focus)\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<img[^>]+src\s*=\s*[\"']?javascript:", re.IGNORECASE),
    re.compile(r"%3cscript", re.IGNORECASE),  # URL 인코딩된 <script
    re.compile(r"document\.cookie", re.IGNORECASE),
]

# 인코딩/난독화 흔적 (확신도는 낮지만 의심스러운 신호 -> LLM 판단 필요)
_SUSPICIOUS_ENCODING = re.compile(r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}")


def check_web_log(log_line: str) -> Detection:
    """웹 서버(nginx/apache) 액세스 로그 한 줄을 검사한다."""
    ip_match = _IP_PATTERN.search(log_line)
    src_ip = ip_match.group(0) if ip_match else "unknown"

    for pat in _SQLI_PATTERNS:
        if pat.search(log_line):
            return Detection(
                True, "SQLi", "confirmed",
                f"SQLi 시그니처 매칭: {pat.pattern}",
                source_ip=src_ip, needs_llm=False,
            )

    for pat in _XSS_PATTERNS:
        if pat.search(log_line):
            return Detection(
                True, "XSS", "confirmed",
                f"XSS 시그니처 매칭: {pat.pattern}",
                source_ip=src_ip, needs_llm=False,
            )

    # 확정 시그니처는 없지만 인코딩된 특수문자가 반복 -> 애매한 케이스, LLM에 위임
    if _SUSPICIOUS_ENCODING.search(log_line):
        return Detection(
            False, "Unknown", "suspicious",
            "반복적인 URL 인코딩 패턴 발견 (알려진 시그니처 불일치)",
            source_ip=src_ip, needs_llm=True,
        )

    return Detection(False, "Normal", "none", "특이 패턴 없음", source_ip=src_ip)
