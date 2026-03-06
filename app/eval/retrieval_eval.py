import json
import argparse
from pathlib import Path
from datetime import datetime

from app.config import DATASET_PATH, RUNS_DIR, TOP_K
from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve

def load_cases(path: Path):
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases

def rank_of_expected(hits, expected_ids):
    expected = {e.upper() for e in expected_ids}
    for idx, (score, rec) in enumerate(hits, start=1):
        rid = (rec.get("cve_id") or "").upper()
        if rid in expected:
            return idx
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=str, default="dataset/eval_cases.jsonl")
    parser.add_argument("--topk", type=int, default=TOP_K)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    cases_path = (root / args.cases).resolve()
    runs_dir = RUNS_DIR

    records = load_jsonl(DATASET_PATH)
    cases = load_cases(cases_path)

    total = len(cases)
    hit_at_k = 0
    mrr_sum = 0.0
    per_case = []

    for c in cases:
        q = c["query"]
        expected = c.get("expected_cve_ids", [])
        hits = retrieve(q, records, top_k=args.topk)

        r = rank_of_expected(hits, expected)
        hit = (r is not None)
        if hit:
            hit_at_k += 1
            mrr_sum += 1.0 / r

        per_case.append({
            "id": c.get("id"),
            "query": q,
            "expected": expected,
            "rank": r,
            "hit": hit,
            "retrieved": [{"cve_id": h[1].get("cve_id"), "score": h[0]} for h in hits],
        })

    recall_k = hit_at_k / total if total else 0.0
    mrr = mrr_sum / total if total else 0.0

    report = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(DATASET_PATH),
        "cases": str(cases_path),
        "top_k": args.topk,
        "metrics": {
            "recall_at_k": recall_k,
            "mrr": mrr,
            "total_cases": total,
        },
        "per_case": per_case,
    }

    runs_dir.mkdir(parents=True, exist_ok=True)
    out = runs_dir / f"eval_retrieval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[OK] Retrieval Eval @K={args.topk}")
    print(f"  cases:  {total}")
    print(f"  Recall@{args.topk}: {recall_k:.3f}")
    print(f"  MRR:    {mrr:.3f}")
    print(f"[OK] saved: {out}")

if __name__ == "__main__":
    main()