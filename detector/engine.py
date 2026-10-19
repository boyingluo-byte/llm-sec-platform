"""检测引擎：规则匹配 + 编码还原链 + 作用域过滤。"""
from __future__ import annotations

import base64
import codecs
import re
from dataclasses import dataclass
from typing import List, Optional

from .dsl import Rule


@dataclass
class Hit:
    rule_id: str
    name: str
    owasp: str
    severity: str
    action: str
    evidence: str


def _b64_variants(text: str) -> List[str]:
    """提取连续 base64 字符块并尝试解码，返回解码成功的文本。"""
    out: List[str] = []
    for m in re.finditer(r"[A-Za-z0-9+/=]{12,}", text):
        chunk = m.group(0)
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded.strip():
            out.append(decoded)
    return out


def _variants(text: str, decoders: List[str]) -> List[str]:
    """原文 + 各编码还原后的候选文本。"""
    variants = [text]
    if "base64" in decoders:
        variants.extend(_b64_variants(text))
    if "rot13" in decoders:
        variants.append(codecs.encode(text, "rot13"))
    if "unicode_escape" in decoders:
        try:
            variants.append(text.encode("utf-8").decode("unicode_escape", "ignore"))
        except Exception:
            pass
    if "reverse" in decoders:
        variants.append(text[::-1])
    return variants


class DetectionEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def detect(self, text: str, scope: str = "all") -> List[Hit]:
        if not text:
            return []
        hits: List[Hit] = []
        for rule in self.rules:
            if scope != "all" and rule.scope != "all" and rule.scope != scope:
                continue
            evidence = self._match_rule(rule, text)
            if evidence:
                hits.append(
                    Hit(rule.id, rule.name, rule.owasp, rule.severity, rule.action, evidence)
                )
        return hits

    @staticmethod
    def _match_rule(rule: Rule, text: str) -> Optional[str]:
        m = rule.match
        for variant in _variants(text, m.decode or []):
            if m.regex:
                mm = rule.compiled().search(variant)
                if mm:
                    note = "" if variant == text else " [编码还原命中]"
                    return f"{mm.group(0)[:60]}{note}"
            if m.keywords:
                low = variant.lower()
                for kw in m.keywords:
                    if kw.lower() in low:
                        note = "" if variant == text else " [编码还原命中]"
                        return f"{kw}{note}"
        return None
