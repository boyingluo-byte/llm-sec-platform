"""红队评测执行器：用例 -> 网关/靶机 -> 判定 -> 结果。"""
from __future__ import annotations

import argparse
import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import httpx
import yaml

from .judge import RuleJudge


@dataclass
class CaseResult:
    case_id: str
    name: str
    kind: str
    owasp: str
    blocked: bool = False
    http_status: int = 0
    attack_succeeded: bool = False
    violation: bool = False
    latency_ms: float = 0.0
    stage: str = ""
    evidence: str = ""
    response_excerpt: str = ""
    expect: str = "clean"


def load_cases(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        cases = yaml.safe_load(f)
    for c in cases:
        c.setdefault("kind", "attack")
        c.setdefault("owasp", "-")
        c.setdefault("success_if", [])
        c.setdefault("expect_absent", [])
        c.setdefault("expect", "clean")
    return cases


def _steps_of(case: dict) -> List[dict]:
    if "steps" in case:
        return case["steps"]
    return [{"action": "chat", "messages": case.get("messages", [])}]


def _err_code(r: httpx.Response) -> str:
    try:
        return str(r.json().get("error", {}).get("code", r.status_code))
    except Exception:
        return str(r.status_code)


class Runner:
    def __init__(self, gateway: httpx.AsyncClient, target: httpx.AsyncClient, api_key: str, judge=None):
        self.gateway = gateway
        self.target = target
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.judge = judge or RuleJudge()

    async def run_case(self, case: dict) -> CaseResult:
        res = CaseResult(
            case_id=case["id"], name=case.get("name", case["id"]),
            kind=case["kind"], owasp=case["owasp"], expect=case.get("expect", "clean"),
        )
        last_text = ""
        for step in _steps_of(case):
            action = step.get("action", "chat")
            if action == "ingest":
                via_gateway = step.get("target") == "gateway"
                client = self.gateway if via_gateway else self.target
                headers = dict(self.headers) if via_gateway else {}
                r = await client.post("/v1/kb/documents", json=step["doc"], headers=headers)
                if r.status_code >= 400:
                    res.blocked = True
                    res.stage = "kb_ingest"
                    res.evidence = _err_code(r)
                    return res
            elif action == "memory":
                r = await self.target.post("/v1/memory", json=step["entry"])
                if r.status_code >= 400:
                    res.blocked = True
                    res.stage = "memory_write"
                    res.evidence = _err_code(r)
                    return res
            else:  # chat
                messages = step.get("messages") or case.get("messages", [])
                t0 = time.perf_counter()
                r = await self.gateway.post(
                    "/v1/chat/completions", headers=self.headers,
                    json={"model": "demo-model", "messages": messages},
                )
                res.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
                res.http_status = r.status_code
                try:
                    data = r.json()
                except Exception:
                    data = {}
                if r.status_code >= 400:
                    res.blocked = True
                    res.stage = "request"
                    res.evidence = _err_code(r)
                    return res
                choices = data.get("choices") or [{}]
                msg = choices[0].get("message") or {}
                last_text = msg.get("content") or ""
                if "[内容安全拦截]" in last_text or choices[0].get("finish_reason") == "content_filter":
                    res.blocked = True
                    res.stage = "response"
                    res.evidence = "DLP 拦截"
                    return res
        res.response_excerpt = last_text[:120]
        verdict = self.judge.judge(case, last_text)
        res.attack_succeeded = verdict.attack_succeeded
        res.violation = verdict.violation
        res.evidence = verdict.evidence
        return res


async def run_suite(cases_path: str, gateway_url: str, target_url: str, api_key: str) -> List[CaseResult]:
    cases = load_cases(cases_path)
    # trust_env=False：本地评测不走环境变量代理
    async with httpx.AsyncClient(base_url=gateway_url, timeout=30, trust_env=False) as gw, \
               httpx.AsyncClient(base_url=target_url, timeout=30, trust_env=False) as tg:
        runner = Runner(gw, tg, api_key)
        return [await runner.run_case(c) for c in cases]


def main() -> None:
    parser = argparse.ArgumentParser(description="红队评测执行器")
    parser.add_argument("--cases", default="redteam/cases/cases.yaml")
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--target", default="http://127.0.0.1:9100")
    parser.add_argument("--key", default="sk-demo-alice")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    from .metrics import summarize
    from .report import render_report

    results = asyncio.run(run_suite(args.cases, args.gateway, args.target, args.key))
    for r in results:
        outcome = "拦截" if r.blocked else ("攻破" if r.attack_succeeded else ("违例" if r.violation else "放行"))
        print(f"[{r.kind:7s}] {r.case_id:8s} {outcome}  {r.name}  ({r.evidence})")
    summary = summarize(results)
    print(f"\n攻击 {summary.attack_total} | 拦截 {summary.attack_blocked} | 检出率 {summary.detection_rate:.0%}")
    print(f"良性 {summary.benign_total} | 误报 {summary.benign_blocked} | 误报率 {summary.fp_rate:.0%}")
    print(f"控制验证 {summary.control_total} | 通过 {summary.control_passed}")
    print(f"时延 P50 {summary.p50_ms:.0f}ms / P95 {summary.p95_ms:.0f}ms")
    if args.out:
        report = render_report(results, summary, {
            "gateway_url": args.gateway, "target_url": args.target,
            "judge": "rule", "rules": 0,
        })
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        print(f"报告: {out}")


if __name__ == "__main__":
    main()
