"""
원격 서버 로그 실시간 수집기 (SSH tail -F 방식)
- 연결 끊김 시 지수 백오프로 재연결 (기존 코드는 고정 5초 재시도라 장애 시 로그 폭주 위험)
- SSH 키 인증을 우선 지원, 없으면 비밀번호 인증으로 폴백
"""
import logging
import time

import paramiko

import config

logger = logging.getLogger("collectors")


class SshLogCollector:
    def __init__(self, host, port, user, log_path, password=None, key_path=None):
        self.host = host
        self.port = port
        self.user = user
        self.log_path = log_path
        self.password = password
        self.key_path = key_path

    def _connect(self) -> paramiko.SSHClient:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = dict(hostname=self.host, port=self.port, username=self.user, timeout=10)
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise RuntimeError("SSH 인증 정보가 없습니다. REMOTE_KEY_PATH 또는 REMOTE_PASS를 설정하세요.")
        ssh.connect(**connect_kwargs)
        return ssh

    def stream(self, on_line):
        """
        신규 로그 라인이 도착할 때마다 on_line(line: str) 콜백을 호출한다.
        연결이 끊기면 지수 백오프로 재연결을 시도하며, 이 함수는 종료되지 않는다.
        """
        delay = config.RECONNECT_BASE_DELAY
        while True:
            ssh = None
            try:
                logger.info(f"[{self.log_path}] {self.host}:{self.port} 연결 시도 중...")
                ssh = self._connect()
                logger.info(f"[{self.log_path}] SSH 연결 성공. 신규 로그 대기 중...")
                delay = config.RECONNECT_BASE_DELAY  # 연결 성공 시 백오프 초기화

                stdin, stdout, stderr = ssh.exec_command(f"tail -n 0 -F {self.log_path}")
                for line in iter(stdout.readline, ""):
                    line = line.strip()
                    if line:
                        on_line(line)

            except Exception as e:
                logger.warning(f"[{self.log_path}] 연결 끊김/에러: {e}. {delay}초 후 재연결")
                time.sleep(delay)
                delay = min(delay * 2, config.RECONNECT_MAX_DELAY)
            finally:
                if ssh:
                    ssh.close()