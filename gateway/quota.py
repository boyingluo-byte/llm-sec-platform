"""令牌桶限流：MVP 内存实现，接口预留 Redis 替换。"""
from __future__ import annotations

import threading
import time
from typing import Dict, Tuple


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.refill = refill_per_sec
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> Tuple[bool, float]:
        """返回 (是否放行, 需等待秒数)。"""
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, 0.0
            return False, (1.0 - self.tokens) / self.refill


class QuotaManager:
    def __init__(self, rpm: int, burst: int):
        self.rpm = max(1, rpm)
        self.burst = max(1, burst)
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check(self, tenant: str, model: str) -> Tuple[bool, float]:
        key = f"{tenant}:{model}"
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self.burst, self.rpm / 60.0)
                self._buckets[key] = bucket
        return bucket.allow()
