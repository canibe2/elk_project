"""
설정 모듈
- 민감정보(비밀번호, 접속정보)는 코드에 직접 넣지 않고 .env에서 로드한다.
- .env 파일은 절대 git에 커밋하지 말 것 (.gitignore에 추가).
"""
import os
from dotenv import load_dotenv

load_dotenv()


def _require(key: str, default=None):
    val = os.getenv(key, default)
    if val is None:
        raise RuntimeError(f"[설정 오류] 환경변수 {key} 가 설정되지 않았습니다. .env 파일을 확인하세요.")
    return val


# --- Elasticsearch ---
ES_HOST = _require("ES_HOST", "http://localhost:9200")
ES_INDEX = _require("ES_INDEX", "ai-security-logs")

# --- Ollama / LLM ---
OLLAMA_URL = _require("OLLAMA_URL", "http://localhost:11434")
MODEL_NAME = _require("OLLAMA_MODEL", "gemma2:2b")
LLM_TIMEOUT_SEC = int(os.getenv("LLM_TIMEOUT_SEC", "30"))

# --- 원격 서버 (SSH 로그 수집 대상) ---
REMOTE_HOST = _require("REMOTE_HOST", "127.0.0.1")
REMOTE_PORT = int(os.getenv("REMOTE_PORT", "22"))
REMOTE_USER = _require("REMOTE_USER", "ubuntu")
REMOTE_PASS = os.getenv("REMOTE_PASS")  # 가능하면 REMOTE_KEY_PATH 사용 권장
REMOTE_KEY_PATH = os.getenv("REMOTE_KEY_PATH")  # SSH 키 인증 (권장)

AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
WEB_LOG_PATH = os.getenv("WEB_LOG_PATH", "/var/log/nginx/access.log")

# --- 브루트포스 탐지 파라미터 ---
BRUTEFORCE_THRESHOLD = int(os.getenv("BRUTEFORCE_THRESHOLD", "5"))   # 임계 시도 횟수
BRUTEFORCE_WINDOW_SEC = int(os.getenv("BRUTEFORCE_WINDOW_SEC", "60"))  # 슬라이딩 윈도우(초)

# --- 재연결 정책 ---
RECONNECT_BASE_DELAY = 3
RECONNECT_MAX_DELAY = 60
