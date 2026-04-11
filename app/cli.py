import json
import argparse
from datetime import datetime

from .config import DATASET_PATH, RUNS_DIR, TOP_K
from .io.dataset_loader import load_jsonl
from .retrieval.simple_retriever import retrieve
from .rag.answer import build_answer
from .logging.run_logger import log_run
from .rag.generate import generate_rag_answer


def _shorten(text: str, max_len: int = 160) -> str:
    text = (text or "").replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def print_retrieval_preview(query: str, hits):
    print("\n=== RETRIEVAL PREVIEW ===\n")
    print(f"query: {query}")
    print(f"hits: {len(hits)}\n")

    if not hits:
        print("[NO HITS]")
        print("\n=== END RETRIEVAL ===\n")
        return

    for i, (score, rec) in enumerate(hits, start=1):
        print(f"[HIT {i}]")
        print(f"score: {score:.3f}")
        print(f"cve_id: {rec.get('cve_id')}")
        print(f"kev: {rec.get('kev')}")
        print(f"cwe_primary_id: {rec.get('cwe_primary_id')}")
        print(f"cwe_top_id: {rec.get('cwe_top_id')}")
        print(f"description: {_shorten(rec.get('description') or '')}")
        refs = rec.get("references") or []
        if refs:
            print(f"reference_1: {refs[0]}")
        print()

    print("=== END RETRIEVAL ===\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("query", type=str, help="User query (CVE id / question)")
    parser.add_argument("--topk", type=int, default=TOP_K)
    parser.add_argument("--dump-prompt", action="store_true", help="Print RAG prompt preview")
    parser.add_argument("--dump-retrieval", action="store_true", help="Print retrieval preview before final answer")
    parser.add_argument("--use-llm", action="store_true", help="Use RAG generation layer")
    parser.add_argument("--llm-mode", type=str, default="mock", help="LLM mode: mock | ollama")
    args = parser.parse_args()

    records = load_jsonl(DATASET_PATH)
    hits = retrieve(args.query, records, top_k=args.topk)

    if args.dump_retrieval:
        print_retrieval_preview(args.query, hits)

    fallback_answer = build_answer(args.query, hits)

    rag_result = None
    final_answer = fallback_answer

    if args.use_llm:
        rag_result = generate_rag_answer(
            query=args.query,
            hits=hits,
            fallback_answer=fallback_answer,
            mode=args.llm_mode,
        )
        final_answer = rag_result["llm_answer"]

    payload = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "query": args.query,
        "top_k": args.topk,
        "retrieval": [
            {
                "score": s,
                "cve_id": r.get("cve_id"),
                "kev": r.get("kev"),
                "cwe_primary_id": r.get("cwe_primary_id"),
                "cwe_top_id": r.get("cwe_top_id"),
                "description_preview": _shorten(r.get("description") or "", max_len=180),
            }
            for s, r in hits
        ],
        "fallback_answer": fallback_answer,
        "rag_result": rag_result,
        "final_answer": final_answer,
        "meta": {
            "retriever": "simple_v0_exact_plus_rules",
            "dataset": str(DATASET_PATH),
            "prompt_preview_enabled": args.dump_prompt,
            "retrieval_preview_enabled": args.dump_retrieval,
            "use_llm": args.use_llm,
            "llm_mode": args.llm_mode,
        },
    }

    out_path = log_run(RUNS_DIR, payload)

    if args.dump_prompt and rag_result is not None:
        print("\n=== RAG PROMPT PREVIEW ===\n")
        print(rag_result["prompt"])
        print("\n=== END PROMPT ===\n")

    print(json.dumps(final_answer, ensure_ascii=False, indent=2))
    print(f"\n[OK] log saved: {out_path}")


if __name__ == "__main__":
    main()