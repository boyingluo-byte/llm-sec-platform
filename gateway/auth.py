"""API Key 认证：常量时间比较，密钥 -> 租户映射。"""
from __future__ import annotations

import hmac
from typing import Dict, Optional


class Authenticator:
    def __init__(self, keys: Dict[str, str]):
        self._keys = dict(keys)

    def tenant_for(self, authorization: Optional[str]) -> Optional[str]:
        if not authorization:
            return None
        parts = authorization.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        token = parts[1].strip()
        for key, tenant in self._keys.items():
            if hmac.compare_digest(key, token):
                return tenant
        return None
