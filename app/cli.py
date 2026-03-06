import json
import argparse
from datetime import datetime

from .config import DATASET_PATH, RUNS_DIR, TOP_K
from .io.dataset_loader import load_jsonl
from .retrieval.simple_retriever import retrieve
from .rag.answer import build_answer
from .logging.run_logger import log_run

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("query", type=str, help="User query (CVE id / question)")
    parser.add_argument("--topk", type=int, default=TOP_K)
    args = parser.parse_args()

    records = load_jsonl(DATASET_PATH)
    hits = retrieve(args.query, records, top_k=args.topk)
    answer = build_answer(args.query, hits)

    payload = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "query": args.query,
        "top_k": args.topk,
        "retrieval": [{"score": s, "cve_id": r.get("cve_id")} for s, r in hits],
        "answer": answer,
        "meta": {"retriever": "simple_v0", "dataset": str(DATASET_PATH)},
    }

    out_path = log_run(RUNS_DIR, payload)

    print(json.dumps(answer, ensure_ascii=False, indent=2))
    print(f"\n[OK] log saved: {out_path}")

if __name__ == "__main__":
    main()