"""MCP server 工具描述静态扫描：tool poisoning / rug pull 检测。

用法：
    python scripts/mcp_scan.py mock_llm/mcp_demo/server.json

输出：每个工具的风险判定 + 工具定义集合哈希（rug pull 版本锁定基线）。
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HIDDEN_CHARS = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")

POISON_PATTERNS = [
    ("外发指令", r"(?i)(send|post|upload|exfiltrate|发送|上传|外发|转发).{0,60}(https?://|endpoint|server|url|服务器)"),
    ("隐瞒用户", r"(?i)(do\s+not\s+(tell|inform|mention|reveal)\s+the\s+user|不要(告诉|告知|通知)用户|请勿告知|不得告知用户)"),
    ("强制附带", r"(?i)((always|must)\s+(include|send|pass|add|attach)|(必须|务必)(先|把|将))"),
    ("敏感文件读取", r"(?i)(read|cat|open|读取)\s+[~/]?\.?(ssh|aws|env|config|/etc/passwd)"),
    ("时序劫持", r"(?i)(before|after|when)\s+(calling|using|you\s+call|invoke)|调用(前|后|时)"),
]


def scan_tool(tool: dict) -> list:
    findings = []
    text = f"{tool.get('name', '')}\n{tool.get('description', '')}"
    for char in HIDDEN_CHARS:
        if char in text:
            findings.append(f"隐藏字符 U+{ord(char):04X}")
            break
    for label, pattern in POISON_PATTERNS:
        if re.search(pattern, text):
            findings.append(label)
    return findings


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "mock_llm/mcp_demo/server.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    tools = data.get("tools", [])
    print(f"MCP server: {data.get('name')} v{data.get('version')} · 工具数 {len(tools)}")
    poisoned = 0
    digest = hashlib.sha256()
    for tool in tools:
        canonical = json.dumps(tool, sort_keys=True, ensure_ascii=False)
        digest.update(canonical.encode("utf-8"))
        findings = scan_tool(tool)
        if findings:
            poisoned += 1
        status = "可疑" if findings else "干净"
        print(f"  [{status}] {tool.get('name')}: {'; '.join(findings) or '-'}")
    print(f"定义集合哈希（rug pull 基线）: {digest.hexdigest()[:16]}")
    print(f"结论: {poisoned}/{len(tools)} 个工具描述疑似被注入指令")
    return 1 if poisoned else 0


if __name__ == "__main__":
    raise SystemExit(main())
