"""检测规则 DSL：YAML 声明式规则 -> Rule 对象。

规则即代码：每条规则必须带正反例单测（见 tests/test_rules.py）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

VALID_ACTIONS = ("block", "flag", "log")
VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_SCOPES = ("request", "response", "all")


@dataclass
class Matcher:
    regex: Optional[str] = None
    keywords: Optional[List[str]] = None
    decode: Optional[List[str]] = None


@dataclass
class Rule:
    id: str
    name: str
    owasp: str
    severity: str
    action: str
    scope: str
    match: Matcher
    description: str = ""
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compiled(self) -> Optional[re.Pattern]:
        if self._compiled is None and self.match.regex:
            self._compiled = re.compile(self.match.regex, re.IGNORECASE | re.DOTALL)
        return self._compiled


def _build_rule(raw: dict, index: int) -> Rule:
    where = f"rules[{index}]"
    for key in ("id", "name", "owasp", "match"):
        if key not in raw:
            raise ValueError(f"{where} 缺少必填字段 {key}")
    m = raw["match"] or {}
    if not any(k in m for k in ("regex", "keywords")):
        raise ValueError(f"{where} ({raw['id']}) match 至少需要 regex 或 keywords")
    action = raw.get("action", "block")
    if action not in VALID_ACTIONS:
        raise ValueError(f"{raw['id']} 非法 action: {action}")
    severity = raw.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"{raw['id']} 非法 severity: {severity}")
    scope = raw.get("scope", "all")
    if scope not in VALID_SCOPES:
        raise ValueError(f"{raw['id']} 非法 scope: {scope}")
    if m.get("regex"):
        try:
            re.compile(m["regex"])
        except re.error as e:
            raise ValueError(f"{raw['id']} 正则编译失败: {e}") from e
    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        owasp=str(raw["owasp"]),
        severity=severity,
        action=action,
        scope=scope,
        match=Matcher(
            regex=m.get("regex"),
            keywords=list(m.get("keywords") or []),
            decode=list(m.get("decode") or []),
        ),
        description=str(raw.get("description", "")),
    )


def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        raw_list = yaml.safe_load(f)
    if not isinstance(raw_list, list):
        raise ValueError(f"规则文件 {path} 顶层必须是列表")
    rules = [_build_rule(raw, i) for i, raw in enumerate(raw_list)]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("规则 id 重复")
    return rules
