"""平台配置：环境变量优先，默认值面向本地 demo。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _resolve(path: str) -> str:
    p = Path(path)
    return str(p if p.is_absolute() else PROJECT_ROOT / p)


@dataclass
class Settings:
    backend_url: str = "http://127.0.0.1:9100/v1"
    api_keys: dict = field(default_factory=lambda: {
        "sk-demo-alice": "tenant-a",
        "sk-demo-bob": "tenant-b",
    })
    rate_limit_rpm: int = 60
    burst: int = 10
    shadow_mode: bool = False
    audit_log_path: str = "reports/audit.jsonl"
    rules_path: str = "detector/rules/rules.yaml"

    def __post_init__(self) -> None:
        self.audit_log_path = _resolve(self.audit_log_path)
        self.rules_path = _resolve(self.rules_path)

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls()
        s.backend_url = os.getenv("LSG_BACKEND_URL", s.backend_url)
        s.rate_limit_rpm = int(os.getenv("LSG_RATE_LIMIT_RPM", s.rate_limit_rpm))
        s.burst = int(os.getenv("LSG_BURST", s.burst))
        s.shadow_mode = _bool("LSG_SHADOW_MODE", s.shadow_mode)
        s.audit_log_path = os.getenv("LSG_AUDIT_LOG", s.audit_log_path)
        s.rules_path = os.getenv("LSG_RULES", s.rules_path)
        return s
