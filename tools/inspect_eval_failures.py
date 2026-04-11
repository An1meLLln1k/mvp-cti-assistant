import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "runs"


def main():
    reports = sorted(RUNS_DIR.glob("eval_retrieval_*.json"))
    if not reports:
        raise FileNotFoundError("Не найдено ни одного eval_retrieval_*.json в папке runs/")

    latest = reports[-1]
    print(f"[INFO] Latest report: {latest}")

    data = json.loads(latest.read_text(encoding="utf-8"))
    cases = data.get("cases", [])

    failed_positive = []
    failed_negative = []

    for c in cases:
        if c.get("type") == "positive" and not c.get("hit@k", False):
            failed_positive.append(c)
        if c.get("type") == "negative" and not c.get("no_hits", False):
            failed_negative.append(c)

    result = {
        "report": str(latest),
        "failed_positive_count": len(failed_positive),
        "failed_negative_count": len(failed_negative),
        "failed_positive": failed_positive,
        "failed_negative": failed_negative,
    }

    out_path = RUNS_DIR / "failed_cases_latest.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[OK] failed_positive: {len(failed_positive)}")
    print(f"[OK] failed_negative: {len(failed_negative)}")
    print(f"[OK] saved: {out_path}")

    if failed_positive:
        print("\n=== FAILED POSITIVE CASES ===")
        for c in failed_positive:
            print(f"- {c.get('id')}: {c.get('query')}")
            print(f"  expected: {c.get('expected')}")
            print(f"  got: {c.get('got')}")

    if failed_negative:
        print("\n=== FAILED NEGATIVE CASES ===")
        for c in failed_negative:
            print(f"- {c.get('id')}: {c.get('query')}")
            print(f"  got: {c.get('got')}")


if __name__ == "__main__":
    main()