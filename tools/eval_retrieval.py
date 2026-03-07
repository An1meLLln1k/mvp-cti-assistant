import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json
from datetime import datetime

from app.config import DATASET_PATH, RUNS_DIR
from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve


def reciprocal_rank(rank):
    return 0.0 if rank is None else 1.0 / rank


def main():
    candidates = [
        ROOT / "dataset" / "benchmark_v0.jsonl",
        ROOT / "dataset" / "eval_cases.jsonl",
        ROOT / "dataset" / "benchmark_tiny.jsonl",
    ]

    bench_path = next((p for p in candidates if p.exists()), None)
    if bench_path is None:
        raise FileNotFoundError(
            "Не найден бенчмарк. Ожидаю один из файлов:\n" + "\n".join(str(p) for p in candidates)
        )

    print(f"[INFO] BENCH: {bench_path}")
    print(f"[INFO] DATASET: {DATASET_PATH}")

    records = load_jsonl(Path(DATASET_PATH))

    cases = []
    with bench_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))

    if not cases:
        raise ValueError(f"Бенчмарк пустой: {bench_path}")

    K = 3

    pos_cases = 0
    pos_hits = 0
    rr_sum = 0.0

    neg_cases = 0
    neg_correct = 0

    per_case = []

    for c in cases:
        q = c.get("query", "")
        expected = [x.upper() for x in c.get("expected_cve_ids", [])]

        got = retrieve(q, records, top_k=K)
        got_ids = [(r.get("cve_id") or "").upper() for _, r in got]

        if expected:
            pos_cases += 1

            rank = None
            for i, cid in enumerate(got_ids, start=1):
                if cid in expected:
                    rank = i
                    break

            hit = rank is not None
            if hit:
                pos_hits += 1
            rr_sum += reciprocal_rank(rank)

            per_case.append(
                {
                    "id": c.get("id"),
                    "type": "positive",
                    "query": q,
                    "expected": expected,
                    "got": got_ids,
                    "hit@k": hit,
                    "rank": rank,
                }
            )
        else:
            neg_cases += 1
            no_hits = len(got_ids) == 0
            if no_hits:
                neg_correct += 1

            per_case.append(
                {
                    "id": c.get("id"),
                    "type": "negative",
                    "query": q,
                    "expected": [],
                    "got": got_ids,
                    "no_hits": no_hits,
                }
            )

    recall_k = pos_hits / pos_cases if pos_cases > 0 else 0.0
    mrr = rr_sum / pos_cases if pos_cases > 0 else 0.0
    no_hit_accuracy = neg_correct / neg_cases if neg_cases > 0 else 0.0

    report = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(DATASET_PATH),
        "benchmark": str(bench_path),
        "K": K,
        "n_cases": len(cases),
        "positive_cases": pos_cases,
        "negative_cases": neg_cases,
        "recall@K": recall_k,
        "mrr": mrr,
        "no_hit_accuracy": no_hit_accuracy,
        "cases": per_case,
    }

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RUNS_DIR / f"eval_retrieval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"n_cases: {len(cases)}")
    print(f"positive_cases: {pos_cases}")
    print(f"negative_cases: {neg_cases}")
    print(f"Recall@{K}: {recall_k:.3f}")
    print(f"MRR: {mrr:.3f}")
    print(f"No-hit accuracy: {no_hit_accuracy:.3f}")
    print(f"[OK] report saved: {out_path}")


if __name__ == "__main__":
    main()