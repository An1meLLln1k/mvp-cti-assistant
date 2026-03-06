import sys
from pathlib import Path

# чтобы можно было импортировать app/* при запуске python tools/eval_retrieval.py
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json
from datetime import datetime

from app.config import DATASET_PATH, RUNS_DIR
from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve


def mrr(rank: int | None) -> float:
    return 0.0 if rank is None else 1.0 / rank


def main() -> None:
    # 1) найти бенчмарк
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

    # 2) загрузить датасет
    records = load_jsonl(Path(DATASET_PATH))

    # 3) загрузить кейсы
    cases = []
    with bench_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))

    if not cases:
        raise ValueError(f"Бенчмарк пустой: {bench_path}")

    # 4) прогон
    K = 3
    hits_at_k = 0
    mrr_sum = 0.0
    per_case = []

    for c in cases:
        q = c.get("query", "")
        expected = set(x.upper() for x in c.get("expected_cve_ids", []))

        got = retrieve(q, records, top_k=K)
        got_ids = [(r.get("cve_id") or "").upper() for _, r in got]

        rank = None
        for i, cid in enumerate(got_ids, start=1):
            if cid in expected:
                rank = i
                break

        hit = rank is not None
        hits_at_k += 1 if hit else 0
        mrr_sum += mrr(rank)

        per_case.append(
            {
                "id": c.get("id"),
                "query": q,
                "expected": list(expected),
                "got": got_ids,
                "hit@k": hit,
                "rank": rank,
            }
        )

    recall_k = hits_at_k / max(1, len(cases))
    mrr_val = mrr_sum / max(1, len(cases))

    # 5) сохранить отчёт
    report = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(DATASET_PATH),
        "benchmark": str(bench_path),
        "K": K,
        "n_cases": len(cases),
        "recall@K": recall_k,
        "mrr": mrr_val,
        "cases": per_case,
    }

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RUNS_DIR / f"eval_retrieval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"n_cases: {len(cases)}")
    print(f"Recall@{K}: {recall_k:.3f}")
    print(f"MRR: {mrr_val:.3f}")
    print(f"[OK] report saved: {out_path}")


if __name__ == "__main__":
    main()