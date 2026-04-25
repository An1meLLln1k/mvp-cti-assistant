import csv
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from statistics import mean

from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve
from app.rag.answer import build_answer
from app.rag.generate import generate_rag_answer
from app.config import DATASET_PATH


TOP_K_EVAL = 3
LLM_MODE = "ollama"
BENCHMARK_PATH = Path("dataset/benchmark_generation_v1.jsonl")


def load_cases(path: Path):
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)

            case_id = item.get("id") or item.get("case_id")
            scenario = item.get("scenario")
            query = item.get("query")
            expected_cve_ids = item.get("expected_cve_ids", [])

            if not isinstance(expected_cve_ids, list):
                expected_cve_ids = []

            if not case_id or not scenario or not query:
                raise ValueError(f"Некорректный кейс в benchmark: {item}")

            expected_type = "no_hit" if len(expected_cve_ids) == 0 else "hit"

            cases.append(
                {
                    "case_id": case_id,
                    "scenario": scenario,
                    "query": query,
                    "expected_type": expected_type,
                    "expected_cve_ids": expected_cve_ids,
                }
            )
    return cases


def sanitize_model_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name.replace(":", "_"))


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def extract_display_fields(final_answer, fallback_answer, hits):
    """
    Приводим ответы к единому плоскому виду,
    чтобы потом их было удобно сравнивать между моделями.
    """
    if not hits:
        return {
            "summary": "По запросу не найден релевантный контекст в локальном корпусе.",
            "actions": [],
            "kev": False,
            "grounded": False,
            "cwe_primary": None,
            "cwe_top": None,
            "references": [],
            "notes": (
                "Надёжное совпадение в корпусе не найдено. "
                "Результат не следует трактовать как подтверждённую информацию "
                "по конкретной уязвимости."
            ),
        }

    if isinstance(final_answer, dict) and "items" not in final_answer:
        cwe = final_answer.get("cwe") or {}
        return {
            "summary": final_answer.get("summary") or "",
            "actions": final_answer.get("actions") or [],
            "kev": bool(final_answer.get("kev")),
            "grounded": bool(final_answer.get("grounded")),
            "cwe_primary": cwe.get("primary"),
            "cwe_top": cwe.get("top"),
            "references": final_answer.get("references") or [],
            "notes": final_answer.get("notes") or "",
        }

    items = fallback_answer.get("items") or []
    top = items[0] if items else {}
    cwe = top.get("cwe") or {}
    return {
        "summary": fallback_answer.get("summary") or "",
        "actions": fallback_answer.get("actions") or [],
        "kev": bool(top.get("kev")),
        "grounded": bool(hits),
        "cwe_primary": cwe.get("primary"),
        "cwe_top": cwe.get("top"),
        "references": top.get("references") or [],
        "notes": "Результат сформирован без интерпретации языковой моделью.",
    }


def top_hit_info(hits):
    if not hits:
        return {
            "retrieval_found": False,
            "top1_score": None,
            "top1_cve_id": None,
            "top1_kev": None,
            "top1_cwe_primary": None,
            "top1_cwe_top": None,
        }

    score, rec = hits[0]
    return {
        "retrieval_found": True,
        "top1_score": float(score),
        "top1_cve_id": rec.get("cve_id"),
        "top1_kev": rec.get("kev"),
        "top1_cwe_primary": rec.get("cwe_primary_id"),
        "top1_cwe_top": rec.get("cwe_top_id"),
    }


def build_manual_scoring_rows(results):
    rows = []
    for r in results:
        rows.append(
            {
                "model": r["model"],
                "case_id": r["case_id"],
                "scenario": r["scenario"],
                "query": r["query"],
                "expected_type": r["expected_type"],
                "expected_cve_ids_joined": " | ".join(r.get("expected_cve_ids", [])),
                "retrieval_found": r["retrieval_found"],
                "top1_cve_id": r["top1_cve_id"],
                "top1_expected_match": r["top1_expected_match"],
                "duration_sec": r["duration_sec"],
                "summary": r["summary"],
                "actions_joined": " | ".join(r["actions"]),
                "notes": r["notes"],
                "score_summary_correctness_0_2": "",
                "score_no_hallucination_0_2": "",
                "score_no_hit_behavior_0_2": "",
                "score_readability_0_2": "",
                "comment": "",
            }
        )
    return rows


def save_csv(path: Path, rows):
    if not rows:
        return

    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
    model_safe = sanitize_model_name(model_name)
    stamp = now_stamp()
    cases = load_cases(BENCHMARK_PATH)

    out_dir = Path("runs") / f"generation_compare_{model_safe}_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("СРАВНИТЕЛЬНАЯ ОЦЕНКА GENERATION-КОМПОНЕНТА")
    print(f"Модель: {model_name}")
    print(f"Корпус: {DATASET_PATH}")
    print(f"Benchmark: {BENCHMARK_PATH}")
    print(f"Top-K retrieval: {TOP_K_EVAL}")
    print(f"Кейсов: {len(cases)}")
    print(f"Результаты будут сохранены в: {out_dir}")
    print("=" * 80)

    records = load_jsonl(DATASET_PATH)
    results = []

    for idx, case in enumerate(cases, start=1):
        query = case["query"]
        case_id = case["case_id"]
        scenario = case["scenario"]
        expected_type = case["expected_type"]
        expected_cve_ids = case.get("expected_cve_ids", [])

        print(f"\n[{idx}/{len(cases)}] {case_id} | {scenario}")
        print(f"Запрос: {query}")

        started_at = time.perf_counter()

        try:
            hits = retrieve(query, records, top_k=TOP_K_EVAL)
            fallback_answer = build_answer(query, hits)

            rag_result = generate_rag_answer(
                query=query,
                hits=hits,
                fallback_answer=fallback_answer,
                mode=LLM_MODE,
            )

            final_answer = rag_result["llm_answer"]
            raw_llm_answer = rag_result.get("raw_llm_answer")
            prompt = rag_result.get("prompt")

            elapsed = round(time.perf_counter() - started_at, 3)

            flat = extract_display_fields(final_answer, fallback_answer, hits)
            top1 = top_hit_info(hits)

            top1_expected_match = (
                top1["top1_cve_id"] in expected_cve_ids if expected_cve_ids else (top1["top1_cve_id"] is None)
            )

            result = {
                "model": model_name,
                "case_id": case_id,
                "scenario": scenario,
                "query": query,
                "expected_type": expected_type,
                "expected_cve_ids": expected_cve_ids,
                "duration_sec": elapsed,
                "retrieval_found": top1["retrieval_found"],
                "top1_score": top1["top1_score"],
                "top1_cve_id": top1["top1_cve_id"],
                "top1_expected_match": top1_expected_match,
                "top1_kev": top1["top1_kev"],
                "top1_cwe_primary": top1["top1_cwe_primary"],
                "top1_cwe_top": top1["top1_cwe_top"],
                "summary": flat["summary"],
                "actions": flat["actions"],
                "actions_count": len(flat["actions"]),
                "kev": flat["kev"],
                "grounded": flat["grounded"],
                "cwe_primary": flat["cwe_primary"],
                "cwe_top": flat["cwe_top"],
                "references": flat["references"],
                "references_count": len(flat["references"]),
                "notes": flat["notes"],
                "final_answer": final_answer,
                "fallback_answer": fallback_answer,
                "raw_llm_answer": raw_llm_answer,
                "prompt": prompt,
            }

            results.append(result)

            print(f"  retrieval_found   = {result['retrieval_found']}")
            print(f"  top1_cve_id       = {result['top1_cve_id']}")
            print(f"  top1_match        = {result['top1_expected_match']}")
            print(f"  grounded          = {result['grounded']}")
            print(f"  duration_sec      = {result['duration_sec']}")
            print(f"  summary           = {result['summary'][:120]}")

        except Exception as exc:
            elapsed = round(time.perf_counter() - started_at, 3)
            error_result = {
                "model": model_name,
                "case_id": case_id,
                "scenario": scenario,
                "query": query,
                "expected_type": expected_type,
                "expected_cve_ids": expected_cve_ids,
                "duration_sec": elapsed,
                "error": f"{type(exc).__name__}: {exc}",
            }
            results.append(error_result)
            print(f"  ERROR: {error_result['error']}")

    json_path = out_dir / f"generation_results_{model_safe}.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    valid_results = [r for r in results if "error" not in r]
    scoring_rows = build_manual_scoring_rows(valid_results)
    csv_path = out_dir / f"manual_scoring_template_{model_safe}.csv"
    save_csv(csv_path, scoring_rows)

    durations = [r["duration_sec"] for r in valid_results if r.get("duration_sec") is not None]
    actions_counts = [r["actions_count"] for r in valid_results]
    refs_counts = [r["references_count"] for r in valid_results]
    retrieval_found_count = sum(1 for r in valid_results if r["retrieval_found"])
    grounded_count = sum(1 for r in valid_results if r["grounded"])
    top1_match_count = sum(1 for r in valid_results if r["top1_expected_match"])
    error_count = sum(1 for r in results if "error" in r)

    summary = {
        "model": model_name,
        "benchmark_path": str(BENCHMARK_PATH),
        "cases_total": len(results),
        "cases_ok": len(valid_results),
        "cases_error": error_count,
        "retrieval_found_count": retrieval_found_count,
        "top1_expected_match_count": top1_match_count,
        "grounded_count": grounded_count,
        "avg_duration_sec": round(mean(durations), 3) if durations else None,
        "avg_actions_count": round(mean(actions_counts), 3) if actions_counts else None,
        "avg_references_count": round(mean(refs_counts), 3) if refs_counts else None,
        "output_dir": str(out_dir),
        "json_path": str(json_path),
        "csv_path": str(csv_path),
    }

    summary_path = out_dir / f"summary_{model_safe}.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 80)
    print("ГОТОВО")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("=" * 80)


if __name__ == "__main__":
    main()