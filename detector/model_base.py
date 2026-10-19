"""模型检测插件接口（W4 微调落地占位）。

线上引擎 = 规则层 + 模型层。MVP 仅规则层；接口先行，
微调好的 BERT 分类器实现同一接口即可热插拔（blended 判定）。
"""
from __future__ import annotations

from typing import List


class ModelDetector:
    """模型层检测器接口。"""

    name = "base"

    def detect(self, text: str) -> List[dict]:
        """返回 [{"score": float, "label": "malicious"|"benign", "model": str}]"""
        raise NotImplementedError


class HeuristicModelDetector(ModelDetector):
    """无模型依赖的占位实现：演示 blended 判定接口（规则 + 模型加权）。"""

    name = "heuristic-stub"

    SUSPICIOUS = ("忽略", "instruction", "prompt", "dan", "越狱", "系统提示")

    def detect(self, text: str) -> List[dict]:
        low = text.lower()
        hits = sum(1 for s in self.SUSPICIOUS if s in low)
        label = "malicious" if hits else "benign"
        return [{"score": min(1.0, hits / 3.0), "label": label, "model": self.name}]
