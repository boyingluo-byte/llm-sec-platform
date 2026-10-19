"""后端转发客户端 + 流式响应守卫。"""
from __future__ import annotations

import json
from typing import AsyncIterator, Dict, Optional

import httpx

from common.schemas import ChatCompletionRequest
from detector.engine import DetectionEngine, Hit


class BackendClient:
    def __init__(self, base_url: str, timeout: float = 60.0, transport: Optional[httpx.BaseTransport] = None):
        # trust_env=False：本地转发不走环境变量代理，保证路由确定
        self._client = httpx.AsyncClient(
            base_url=base_url, timeout=timeout, transport=transport, trust_env=False
        )

    async def chat(self, req: ChatCompletionRequest, headers: Optional[Dict[str, str]] = None) -> dict:
        r = await self._client.post(
            "/chat/completions", json=req.model_dump(exclude_none=True), headers=headers or {}
        )
        r.raise_for_status()
        return r.json()

    async def post_json(self, path: str, payload: dict, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        return await self._client.post(path, json=payload, headers=headers or {})

    async def stream(self, req: ChatCompletionRequest, headers: Optional[Dict[str, str]] = None) -> AsyncIterator[str]:
        async with self._client.stream(
            "POST", "/chat/completions", json=req.model_dump(exclude_none=True), headers=headers or {}
        ) as r:
            async for line in r.aiter_lines():
                if line:
                    yield line


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


async def guarded_stream(raw_stream: AsyncIterator[str], engine: DetectionEngine) -> AsyncIterator[str]:
    """流式透传 + 响应侧 DLP：逐 chunk 累积扫描，命中即截断并结束流。"""
    buffer: list = []
    done_seen = False
    async for line in raw_stream:
        if line.startswith("data:"):
            payload = line.split(":", 1)[1].strip()
            if payload == "[DONE]":
                done_seen = True
                yield "data: [DONE]\n\n"
                continue
            try:
                chunk = json.loads(payload)
                delta = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content") or ""
            except Exception:
                delta = ""
            if delta:
                buffer.append(delta)
                hits: list = [
                    h for h in engine.detect("".join(buffer), scope="response") if h.action == "block"
                ]
                if hits:
                    yield _sse({
                        "error": {
                            "code": "security.response_blocked",
                            "message": "响应命中敏感信息外泄策略，已中断生成",
                            "hits": [h.rule_id for h in hits],
                            "type": "security",
                        }
                    })
                    yield "data: [DONE]\n\n"
                    return
        yield line + "\n\n"
    if not done_seen:
        yield "data: [DONE]\n\n"
