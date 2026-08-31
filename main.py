"""
AI 보안 관제 파이프라인 - 메인 오케스트레이터

파이프라인 흐름
  [SSH 로그 수집] -> [Tier1 규칙 엔진] -> (확정) -> [LLM 요약 생성] -> [Elasticsearch 색인]
                                        -> (애매) -> [Tier2 LLM 분류]  -> [Elasticsearch 색인]
                                        -> (정상) -> 폐기 (색인하지 않음, 노이즈 방지)

인증로그(auth.log)와 웹로그(access.log)를 별도 스레드에서 동시에 수집한다.
"""
import logging
import re
import threading
import time
from datetime import datetime, timezone

import config
from collectors import SshLogCollector
from es_client import EsClient
import rule_engine
import ai_analyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")

_TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2})")


def extract_timestamp(log_message: str) -> str:
    match = _TS_PATTERN.match(log_message)
    if match:
        return match.group(1)
    return datetime.now(timezone.utc).isoformat()


class LlmSummaryThrottle:
    """
    동일 (source_ip, attack_type) 조합이 짧은 시간 안에 반복 확정될 때,
    확정 건마다 LLM을 매번 호출하지 않도록 캐시된 요약을 재사용한다.

    배경: sqlmap 같은 자동화 스캐너는 짧은 시간에 같은 시그니처(UNION SELECT 등)로
    수십~수백 건의 요청을 보낸다. 매 건마다 LLM 요약을 새로 생성하면 LLM 호출이
    병목이 되어 파이프라인이 수 분씩 막히는 문제가 실제로 발생했다 (검증 중 확인).
    색인 자체는 매 건 그대로 하되(탐지 카운트는 정확하게 유지), 자연어 요약 생성만
    쿨다운 동안 재사용해서 LLM 호출 횟수를 줄인다.
    """

    def __init__(self, cooldown_sec: int = 30):
        self.cooldown_sec = cooldown_sec
        self._cache = {}  # (source_ip, attack_type) -> (expire_at, ai_result)

    def get_or_call(self, source_ip, attack_type, call_fn):
        key = (source_ip, attack_type)
        now = time.time()
        cached = self._cache.get(key)
        if cached and cached[0] > now:
            result = dict(cached[1])
            result["summary"] = f"[반복 탐지 - 이전 요약 재사용] {result['summary']}"
            return result, True  # True = 캐시 사용(LLM 미호출)

        result = call_fn()
        self._cache[key] = (now + self.cooldown_sec, result)
        return result, False


class DetectionPipeline:
    def __init__(self, es_client: EsClient):
        self.es = es_client
        self._llm_throttle = LlmSummaryThrottle(cooldown_sec=getattr(config, "LLM_SUMMARY_COOLDOWN_SEC", 30))

    def handle_auth_line(self, line: str):
        detection = rule_engine.check_auth_log(line)
        self._handle(line, "auth", detection)

    def handle_web_line(self, line: str):
        detection = rule_engine.check_web_log(line)
        self._handle(line, "web", detection)

    def _handle(self, line: str, log_type: str, detection: rule_engine.Detection):
        ts = extract_timestamp(line)

        # 정상 트래픽은 색인하지 않음 (노이즈로 대시보드를 채우지 않기 위함)
        if detection.confidence == "none":
            return

        if detection.confidence == "confirmed":
            logger.info(f"[확정탐지][{detection.attack_type}] {detection.source_ip} - {detection.reason}")
            ai_result, from_cache = self._llm_throttle.get_or_call(
                detection.source_ip,
                detection.attack_type,
                lambda: ai_analyzer.summarize_confirmed(line, detection.attack_type, detection.reason),
            )
            if from_cache:
                logger.info(f"[LLM 스킵 - 쿨다운 중] {detection.source_ip}/{detection.attack_type}")
            self.es.index_detection(
                timestamp=ts,
                log_type=log_type,
                source_ip=detection.source_ip,
                attack_type=detection.attack_type,
                is_danger=True,
                severity=ai_result["severity"],
                detection_method="rule",
                confidence="confirmed",
                reason=detection.reason,
                ai_summary=ai_result["summary"],
                original_message=line,
            )
            return

        if detection.confidence == "suspicious" and detection.needs_llm:
            logger.info(f"[애매 - LLM 위임] {detection.source_ip} - {detection.reason}")
            ai_result = ai_analyzer.classify_ambiguous(line)
            is_danger = ai_result["is_danger"] == "위험"
            self.es.index_detection(
                timestamp=ts,
                log_type=log_type,
                source_ip=detection.source_ip,
                attack_type=ai_result["attack_type"],
                is_danger=is_danger,
                severity=ai_result["severity"],
                detection_method="llm",
                confidence="suspicious",
                reason=detection.reason,
                ai_summary=ai_result["summary"],
                original_message=line,
            )
            return

        # 브루트포스 관찰중(임계값 미달) 등 -> 색인은 하되 danger는 false로 (추세 확인용)
        if detection.confidence == "suspicious":
            self.es.index_detection(
                timestamp=ts,
                log_type=log_type,
                source_ip=detection.source_ip,
                attack_type=detection.attack_type,
                is_danger=False,
                severity="낮음",
                detection_method="rule",
                confidence="suspicious",
                reason=detection.reason,
                ai_summary=detection.reason,
                original_message=line,
            )


def main():
    logger.info("AI 보안 파이프라인 초기화 중...")
    es_client = EsClient()
    pipeline = DetectionPipeline(es_client)

    auth_collector = SshLogCollector(
        host=config.REMOTE_HOST,
        port=config.REMOTE_PORT,
        user=config.REMOTE_USER,
        log_path=config.AUTH_LOG_PATH,
        password=config.REMOTE_PASS,
        key_path=config.REMOTE_KEY_PATH,
    )
    web_collector = SshLogCollector(
        host=config.REMOTE_HOST,
        port=config.REMOTE_PORT,
        user=config.REMOTE_USER,
        log_path=config.WEB_LOG_PATH,
        password=config.REMOTE_PASS,
        key_path=config.REMOTE_KEY_PATH,
    )

    threads = [
        threading.Thread(target=auth_collector.stream, args=(pipeline.handle_auth_line,), daemon=True),
        threading.Thread(target=web_collector.stream, args=(pipeline.handle_web_line,), daemon=True),
    ]
    for t in threads:
        t.start()

    logger.info("파이프라인 가동 중 (Ctrl+C로 종료)")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("종료 신호 수신, 파이프라인을 종료합니다.")


if __name__ == "__main__":
    main()
