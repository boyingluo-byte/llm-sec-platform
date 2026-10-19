"""一键演示：靶机 + 网关 + 红队套件 -> 基线报告（全部进程内，无需起服务）。"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
from httpx import ASGITransport

from common.config import Settings
from detector.dsl import load_rules
from gateway.main import create_app
from mock_llm.main import app as target_app
from redteam.metrics import summarize
from redteam.report import render_report
from redteam.runner import Runner, load_cases


async def main() -> None:
    settings = Settings.from_env()
    # demo 模式放开限流（限流能力在 tests/test_gateway.py 单独验证）
    settings.rate_limit_rpm = 600
    settings.burst = 100
    rules_count = len(load_rules(settings.rules_path))
    gateway = create_app(settings, transport=ASGITransport(app=target_app))
    gw_client = httpx.AsyncClient(transport=ASGITransport(app=gateway), base_url="http://gw", trust_env=False)
    tgt_client = httpx.AsyncClient(transport=ASGITransport(app=target_app), base_url="http://tgt", trust_env=False)
    runner = Runner(gw_client, tgt_client, "sk-demo-alice")

    cases = load_cases(str(ROOT / "redteam/cases/cases.yaml"))
    results = []
    for case in cases:
        res = await runner.run_case(case)
        results.append(res)
        outcome = "拦截" if res.blocked else ("攻破" if res.attack_succeeded else ("违例" if res.violation else "放行"))
        print(f"[{case['kind']:7s}] {res.case_id:8s} {outcome}  {res.name}  ({res.evidence})")

    summary = summarize(results)
    print()
    print(f"攻击用例 {summary.attack_total} | 拦截 {summary.attack_blocked} | 检出率 {summary.detection_rate:.0%}")
    print(f"良性用例 {summary.benign_total} | 误报 {summary.benign_blocked} | 误报率 {summary.fp_rate:.0%}")
    print(f"控制验证 {summary.control_total} | 通过 {summary.control_passed}")
    print(f"时延 P50 {summary.p50_ms:.0f}ms / P95 {summary.p95_ms:.0f}ms")

    report = render_report(results, summary, {
        "gateway_url": "in-process",
        "target_url": "in-process",
        "judge": "rule",
        "rules": rules_count,
    })
    out = ROOT / "reports" / f"baseline-{time.strftime('%Y%m%d')}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"\n基线报告: {out}")
    print(f"审计日志: {settings.audit_log_path}")

    await gw_client.aclose()
    await tgt_client.aclose()

    # 回归门禁：检出率未满、有误报、控制验证未全过 -> 非零退出（CI 卡点）
    gate_failed = (
        summary.detection_rate < 1.0
        or summary.benign_blocked > 0
        or summary.control_passed != summary.control_total
    )
    if gate_failed:
        print("\n[门禁未通过] 安全基线劣化：检出率/误报率/控制验证 存在回归")
        sys.exit(1)
    print("\n[门禁通过] 检出率 100% / 误报 0 / 控制验证全过")


if __name__ == "__main__":
    asyncio.run(main())
