"""OpenAI 兼容协议模型 + 安全错误信封。"""
from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: object  # str 或多模态分段列表
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = "demo-model"
    messages: List[ChatMessage]
    temperature: float = 0.7
    stream: bool = False
    max_tokens: Optional[int] = None


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class Choice(BaseModel):
    index: int = 0
    message: Optional[ChatMessage] = None
    delta: Optional[ChatMessage] = None
    finish_reason: Optional[str] = None


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Choice]
    usage: Usage = Usage()


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def security_error(code: str, message: str, request_id: str) -> dict:
    """OpenAI 风格错误信封，code 带 security. 前缀便于业务侧识别处置。"""
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "type": "security",
        }
    }


def flatten_message_content(content: object) -> str:
    """把消息内容拍平为纯文本：字符串原样返回；多模态分段取 text 段与 ocr: 伪协议段。

    多模态注入的检测前提：图片 OCR 文本必须和文字一样进入检测引擎。
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for seg in content:
            if not isinstance(seg, dict):
                continue
            if seg.get("type") == "text":
                parts.append(str(seg.get("text", "")))
            elif seg.get("type") == "image_url":
                url = str((seg.get("image_url") or {}).get("url", ""))
                if url.startswith("ocr:"):
                    parts.append(url[4:])
        return "\n".join(p for p in parts if p)
    return str(content)
