"""极简 TF-IDF 检索器（纯 Python，零依赖）。

生产替换路径：Chroma / pgvector / Milvus（见 README）。
中文无分词依赖：字符 unigram + bigram。
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List, Tuple


def tokenize(text: str) -> List[str]:
    text = text.lower()
    latin = re.findall(r"[a-z0-9]+", text)
    cjk = re.findall(r"[\u4e00-\u9fff]", text)
    bigrams = ["".join(cjk[i:i + 2]) for i in range(len(cjk) - 1)]
    return latin + cjk + bigrams


@dataclass
class Doc:
    doc_id: str
    title: str
    content: str
    tenant: str = "tenant-a"
    level: str = "internal"
    poisoned: bool = False


class TfIdfRetriever:
    def __init__(self):
        self.docs: List[Doc] = []
        self._df: dict = {}

    def add(
        self,
        doc_id: str,
        title: str,
        content: str,
        tenant: str = "tenant-a",
        level: str = "internal",
        poisoned: bool = False,
    ) -> None:
        self.docs.append(Doc(doc_id, title, content, tenant, level, poisoned))
        for token in set(tokenize(f"{title} {content}")):
            self._df[token] = self._df.get(token, 0) + 1

    def search(self, query: str, top_k: int = 3, tenant: str = "tenant-a") -> List[Tuple[Doc, float]]:
        query_tokens = set(tokenize(query))
        n = max(1, len(self.docs))
        scored = []
        for doc in self.docs:
            if doc.tenant != tenant:  # 跨租户隔离
                continue
            tf: dict = {}
            for token in tokenize(f"{doc.title} {doc.content}"):
                tf[token] = tf.get(token, 0) + 1
            score = 0.0
            for token in query_tokens:
                if token in tf:
                    idf = math.log((n + 1) / (self._df.get(token, 0) + 1)) + 1.0
                    score += (1.0 + math.log(tf[token])) * idf
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(doc, score) for score, doc in scored[:top_k]]
