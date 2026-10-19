"""基线报告生成（Markdown）。"""
from __future__ import annotations

import platform
import time
from typing import List

from .metrics import Summary, per_category
from .runner import CaseResult


def render_report(results: List[CaseResult], summary: Summary, meta: dict) -> str:
    lines: List[str] = []
    a = lines.append
    a("# LLM 安全网关 · 红队评测基线报告")
    a("")
    a(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    a(f"- 网关：{meta.get('gateway_url')} · 靶机：{meta.get('target_url')}")
    a(f"- 判定器：{meta.get('judge')} · 规则数：{meta.get('rules')} · Python {platform.python_version()}")
    a("")
    a("## 1. 总览")
    a("")
    a("| 指标 | 数值 |")
    a("| --- | --- |")
    a(f"| 攻击用例总数 | {summary.attack_total} |")
    a(f"| 网关拦截数 | {summary.attack_blocked} |")
    a(f"| 攻击成功数（漏报） | {summary.attack_succeeded} |")
    a(f"| **检出率** | **{summary.detection_rate:.0%}** |")
    a(f"| 良性用例数 | {summary.benign_total} |")
    a(f"| 误报数 | {summary.benign_blocked} |")
    a(f"| **误报率** | **{summary.fp_rate:.0%}** |")
    a(f"| 控制验证用例 | {summary.control_total} |")
    a(f"| 控制通过率 | {summary.control_pass_rate:.0%} |")
    a(f"| 请求时延 P50 / P95 | {summary.p50_ms:.0f} ms / {summary.p95_ms:.0f} ms |")
    a("")
    a("## 2. 分攻击类别")
    a("")
    a("| OWASP | 用例数 | 拦截数 | 检出率 |")
    a("| --- | --- | --- | --- |")
    for row in per_category(results):
        a(f"| {row['owasp']} | {row['total']} | {row['blocked']} | {row['rate']} |")
    a("")
    a("## 3. 用例明细")
    a("")
    a("| 用例 | 类型 | OWASP | 结果 | 阶段 | 说明 |")
    a("| --- | --- | --- | --- | --- | --- |")
    for r in results:
        outcome = "拦截" if r.blocked else ("攻破" if r.attack_succeeded else ("违例" if r.violation else "放行"))
        a(f"| {r.case_id} {r.name} | {r.kind} | {r.owasp} | {outcome} | {r.stage or '-'} | {r.evidence} |")
    a("")
    a("## 4. 抽样响应")
    a("")
    shown = 0
    for r in results:
        if r.response_excerpt and shown < 3:
            a(f"**{r.case_id} {r.name}**")
            a("")
            a("```")
            a(r.response_excerpt)
            a("```")
            a("")
            shown += 1
    a("## 5. 复现方式")
    a("")
    a("```bash")
    a("python scripts/demo.py          # 进程内一键复现")
    a("python -m redteam.runner --gateway http://127.0.0.1:8080 --target http://127.0.0.1:9100")
    a("```")
    a("")
    a("## 6. 合规声明")
    a("")
    a("本报告全部用例仅对本地自建靶机执行，测试数据均为伪造；未对任何外部系统发起请求。")
    a("")
    return "\n".join(lines)
