"""检测模型微调脚手架（W4）。

用红队用例库构造正样本、良性用例构造负样本，微调 bert-base-chinese
二分类器（恶意 prompt / 良性 prompt）。

依赖：requirements-ml.txt（torch/transformers，约 2GB）
本仓库的开发环境无 GPU/网络，脚本未经实跑验证——首次使用请先用
--epochs 1 --max-samples 200 做小规模冒烟。

用法：
    pip install -r requirements-ml.txt
    python detector/train.py --output detector/model/finetuned

产出：
    detector/model/finetuned/   # HuggingFace 格式模型（含 tokenizer）
    微调后实现 detector/model_base.py 的 ModelDetector 接口即可接入引擎。
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_dataset(cases_path: str):
    """从红队用例库构造训练集。

    正样本：attack 类用例的用户消息（注入/越狱/投毒触发语）
    负样本：benign 类用例的用户消息 + 规则库的负向描述
    """
    cases = yaml.safe_load(Path(cases_path).read_text(encoding="utf-8"))
    texts, labels = [], []
    for case in cases:
        messages = case.get("messages") or []
        user_text = "\n".join(
            m.get("content", "") if isinstance(m.get("content"), str) else str(m.get("content"))
            for m in messages if m.get("role") == "user"
        ).strip()
        if not user_text:
            continue
        if case.get("kind") == "benign":
            texts.append(user_text)
            labels.append(0)
        else:
            texts.append(user_text)
            labels.append(1)
    return texts, labels


def main() -> None:
    parser = argparse.ArgumentParser(description="检测模型微调")
    parser.add_argument("--cases", default=str(ROOT / "redteam/cases/cases.yaml"))
    parser.add_argument("--base-model", default="bert-base-chinese")
    parser.add_argument("--output", default=str(ROOT / "detector/model/finetuned"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--max-samples", type=int, default=0, help=">0 时截断样本数（冒烟用）")
    args = parser.parse_args()

    texts, labels = load_dataset(args.cases)
    if args.max_samples:
        pairs = list(zip(texts, labels))
        random.shuffle(pairs)
        texts, labels = zip(*pairs[: args.max_samples])
        texts, labels = list(texts), list(labels)
    print(f"样本数: {len(texts)}（正样本 {sum(labels)} / 负样本 {len(labels) - sum(labels)}）")
    if len(set(labels)) < 2:
        raise SystemExit("训练集必须同时包含正负样本")

    import torch
    from datasets import Dataset
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=256, padding="max_length")

    dataset = Dataset.from_dict({"text": texts, "label": labels}).map(tokenize, batched=True)
    split = dataset.train_test_split(test_size=0.2, seed=42)
    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=16,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        report_to=[],
    )

    def compute_metrics(eval_pred):
        import evaluate

        f1 = evaluate.load("f1")
        logits, labels_ = eval_pred
        preds = logits.argmax(axis=-1)
        return f1.compute(predictions=preds, references=labels_)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=split["train"],
        eval_dataset=split["test"],
        compute_metrics=compute_metrics,
    )
    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"模型已保存: {args.output}")
    print("提示: 样本量只有几十条时，先扩充用例库再全量训练；负样本覆盖真实业务分布比堆量更重要")


if __name__ == "__main__":
    main()
