"""安全管控网关：OpenAI 兼容代理 + 认证/配额/双侧检测/审计/熔断。

中间件链：auth -> quota -> detect_request -> forward -> detect_response -> audit
"""
from __future__ import annotations

import json
import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from common.config import Settings
from common.schemas import (
    ChatCompletionRequest,
    flatten_message_content,
    new_request_id,
    security_error,
)
from detector.dsl import load_rules
from detector.engine import DetectionEngine, Hit
from .audit import AuditLogger
from .auth import Authenticator
from .proxy import BackendClient, guarded_stream
from .quota import QuotaManager


def create_app(settings: Optional[Settings] = None, transport: Optional[httpx.BaseTransport] = None) -> FastAPI:
    s = settings or Settings.from_env()
    engine = DetectionEngine(load_rules(s.rules_path))
    auth = Authenticator(s.api_keys)
    quota = QuotaManager(s.rate_limit_rpm, s.burst)
    audit = AuditLogger(s.audit_log_path)
    backend = BackendClient(s.backend_url, transport=transport)
    circuit_breakers: set = set()  # 被熔断的租户

    app = FastAPI(title="LLM 安全网关", version="0.1.0")
    app.state.settings = s

    def _tenant(request: Request) -> Optional[str]:
        return auth.tenant_for(request.headers.get("authorization"))

    def _hits_payload(hits: list) -> list:
        return [h.__dict__ for h in hits]

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "rules": len(engine.rules)}

    @app.post("/v1/chat/completions")
    async def chat(body: ChatCompletionRequest, request: Request):
        request_id = new_request_id()
        started = time.perf_counter()
        tenant = _tenant(request)
        if not tenant:
            audit.log(request_id=request_id, action="auth_failed")
            return JSONResponse(
                status_code=401,
                content=security_error("security.unauthorized", "无效或缺失的 API Key", request_id),
            )
        if tenant in circuit_breakers:
            audit.log(request_id=request_id, tenant=tenant, action="circuit_broken")
            return JSONResponse(
                status_code=503,
                content=security_error("security.circuit_broken", "租户已被熔断，请联系安全运营", request_id),
            )
        ok, retry_after = quota.check(tenant, body.model)
        if not ok:
            audit.log(
                request_id=request_id, tenant=tenant, model=body.model,
                action="rate_limited", retry_after=round(retry_after, 2),
            )
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
                content=security_error(
                    "security.rate_limited", f"超出配额，{retry_after:.1f}s 后重试", request_id
                ),
            )

        text = "\n".join(flatten_message_content(m.content) for m in body.messages)
        hits = engine.detect(text, scope="request")
        blocking = [h for h in hits if h.action == "block"]
        if blocking and not s.shadow_mode:
            audit.log(
                request_id=request_id, tenant=tenant, model=body.model,
                action="blocked", stage="request", hits=_hits_payload(blocking),
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
            )
            return JSONResponse(
                status_code=400,
                content=security_error(
                    "security.request_blocked",
                    "请求命中安全策略: " + ", ".join(sorted({h.rule_id for h in blocking})),
                    request_id,
                ),
            )

        headers = {"X-Tenant-Id": tenant}
        if body.stream:
            audit.log(
                request_id=request_id, tenant=tenant, model=body.model,
                action="allowed", stage="request_stream", hits=[h.rule_id for h in hits],
            )
            return StreamingResponse(
                guarded_stream(backend.stream(body, headers=headers), engine),
                media_type="text/event-stream",
            )

        try:
            resp = await backend.chat(body, headers=headers)
        except httpx.HTTPError as e:
            audit.log(request_id=request_id, tenant=tenant, model=body.model, action="backend_error", error=str(e))
            return JSONResponse(
                status_code=502,
                content=security_error("security.backend_error", "LLM 后端不可用", request_id),
            )

        parts = []
        for c in resp.get("choices", []):
            msg = c.get("message") or {}
            if msg.get("content"):
                parts.append(msg["content"])
        content = "\n".join(parts)
        latency = round((time.perf_counter() - started) * 1000, 1)

        rhits = [h for h in engine.detect(content, scope="response") if h.action == "block"]
        if rhits:
            audit.log(
                request_id=request_id, tenant=tenant, model=body.model,
                action="blocked", stage="response", hits=_hits_payload(rhits), latency_ms=latency,
            )
            for c in resp.get("choices", []):
                msg = c.get("message")
                if isinstance(msg, dict):
                    msg["content"] = "[内容安全拦截] 响应命中敏感信息外泄策略，已替换为安全提示。"
                c["finish_reason"] = "content_filter"
            return JSONResponse(
                status_code=200,
                content=resp,
                headers={"X-AIGC-Disclosure": "AI-generated content; for reference only"},
            )

        audit.log(
            request_id=request_id, tenant=tenant, model=body.model,
            action="allowed", hits=[h.rule_id for h in hits], latency_ms=latency,
        )
        return JSONResponse(
            status_code=200,
            content=resp,
            headers={"X-AIGC-Disclosure": "AI-generated content; for reference only"},
        )

    @app.post("/v1/kb/documents")
    async def kb_ingest(doc: dict, request: Request):
        """知识库入库代理：先过检测引擎（投毒文档拦截），再转发靶机。"""
        request_id = new_request_id()
        tenant = _tenant(request)
        if not tenant:
            return JSONResponse(
                status_code=401,
                content=security_error("security.unauthorized", "无效或缺失的 API Key", request_id),
            )
        text = f"{doc.get('title', '')}\n{doc.get('content', '')}"
        hits = [h for h in engine.detect(text, scope="request") if h.action == "block"]
        if hits and not s.shadow_mode:
            audit.log(
                request_id=request_id, tenant=tenant, action="blocked", stage="kb_ingest",
                hits=_hits_payload(hits),
            )
            return JSONResponse(
                status_code=400,
                content=security_error(
                    "security.request_blocked",
                    "知识库文档疑似投毒: " + ", ".join(sorted({h.rule_id for h in hits})),
                    request_id,
                ),
            )
        r = await backend.post_json("/kb/documents", doc, headers={"X-Tenant-Id": tenant})
        audit.log(request_id=request_id, tenant=tenant, action="kb_ingested", status=r.status_code)
        return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/admin/audit")
    async def admin_audit(limit: int = 50):
        if not os.path.exists(s.audit_log_path):
            return {"events": []}
        with open(s.audit_log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        return {"events": [json.loads(x) for x in lines if x.strip()]}

    @app.post("/admin/rules/reload")
    async def reload_rules():
        nonlocal engine
        engine = DetectionEngine(load_rules(s.rules_path))
        return {"reloaded": len(engine.rules)}

    @app.post("/admin/circuit-breaker")
    async def set_circuit_breaker(request: Request):
        body = await request.json()
        tenant = body.get("tenant")
        enabled = bool(body.get("enabled"))
        if not tenant:
            return JSONResponse(status_code=400, content={"error": "missing tenant"})
        if enabled:
            circuit_breakers.add(tenant)
        else:
            circuit_breakers.discard(tenant)
        audit.log(tenant=tenant, action="circuit_breaker", enabled=enabled)
        return {"tenant": tenant, "circuit_broken": enabled}

    return app


# 模块级 app：支持 uvicorn gateway.main:app 直接启动
app = create_app()
