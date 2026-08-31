"""
Elasticsearch 색인 클라이언트
- 인덱스 매핑을 명시적으로 정의해서 Kibana에서 source_ip, attack_type, severity 등을
  키워드 필드로 바로 집계/필터링할 수 있게 한다. (동적 매핑에 맡기면 text로 잡혀서
  대시보드에서 aggregation이 안 되는 경우가 흔함)
"""
import logging
from datetime import datetime, timezone

from elasticsearch import Elasticsearch, exceptions as es_exceptions

import config

logger = logging.getLogger("es_client")

_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "log_type": {"type": "keyword"},        # auth | web
            "source_ip": {"type": "ip"},
            "attack_type": {"type": "keyword"},      # Brute Force | SQLi | XSS | Normal
            "is_danger": {"type": "boolean"},
            "severity": {"type": "keyword"},         # 낮음/중간/높음/치명적
            "detection_method": {"type": "keyword"}, # rule | llm | hybrid
            "confidence": {"type": "keyword"},        # confirmed | suspicious
            "reason": {"type": "text"},
            "ai_summary": {"type": "text"},
            "original_message": {"type": "text"},
        }
    }
}


class EsClient:
    def __init__(self, host: str = None, index: str = None):
        self.es = Elasticsearch(host or config.ES_HOST)
        self.index = index or config.ES_INDEX
        self._ensure_index()

    def _ensure_index(self):
        try:
            if not self.es.indices.exists(index=self.index):
                self.es.indices.create(index=self.index, body=_MAPPING)
                logger.info(f"인덱스 생성 완료: {self.index}")
        except es_exceptions.ConnectionError as e:
            logger.error(f"Elasticsearch 연결 실패: {e}")
            raise

    def index_detection(
        self,
        *,
        timestamp: str,
        log_type: str,
        source_ip: str,
        attack_type: str,
        is_danger: bool,
        severity: str,
        detection_method: str,
        confidence: str,
        reason: str,
        ai_summary: str,
        original_message: str,
    ):
        doc = {
            "@timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "log_type": log_type,
            "source_ip": source_ip if source_ip != "unknown" else None,
            "attack_type": attack_type,
            "is_danger": is_danger,
            "severity": severity,
            "detection_method": detection_method,
            "confidence": confidence,
            "reason": reason,
            "ai_summary": ai_summary,
            "original_message": original_message,
        }
        try:
            self.es.index(index=self.index, document=doc)
        except Exception as e:
            logger.error(f"색인 실패: {e}")
