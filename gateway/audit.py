"""审计日志：JSONL 追加写，全链路 request_id 贯穿。"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid


class AuditLogger:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, **event) -> dict:
        event.setdefault("ts", round(time.time(), 3))
        event.setdefault("request_id", uuid.uuid4().hex[:12])
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return event
