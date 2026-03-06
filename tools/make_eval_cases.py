import json
from pathlib import Path

def load_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def main():
    root = Path(__file__).resolve().parents[1]
    ds_dir = root / "dataset"

    in_path = ds_dir / "dataset_v1.jsonl"
    if not in_path.exists():
        in_path = ds_dir / "dataset_v0.jsonl"

    out_path = ds_dir / "eval_cases.jsonl"

    rows = load_jsonl(in_path)

    cases = []
    i = 1
    for r in rows:
        cve = r.get("cve_id")
        if not cve:
            continue

        queries = [
            f"{cve}",
            f"что за {cve} и что делать",
            f"дай краткое резюме по {cve}",
        ]
        for q in queries:
            cases.append({
                "id": f"case_{i:03d}",
                "query": q,
                "expected_cve_ids": [cve],
            })
            i += 1

    with out_path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"[OK] Saved cases: {out_path} (n={len(cases)})")

if __name__ == "__main__":
    main()