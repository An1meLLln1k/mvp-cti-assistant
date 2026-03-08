import json
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", default=str(DATASET_DIR / "dataset_v2.jsonl"))
    parser.add_argument("--hier", default=str(DATASET_DIR / "cwe_hierarchy.json"))
    parser.add_argument("--out", default=str(DATASET_DIR / "dataset_v2_enriched.jsonl"))
    args = parser.parse_args()

    in_path = Path(args.in_path)
    hier_path = Path(args.hier)
    out_path = Path(args.out)

    print(f"[INFO] IN:   {in_path}")
    print(f"[INFO] HIER: {hier_path}")
    print(f"[INFO] OUT:  {out_path}")

    if not in_path.exists():
        raise FileNotFoundError(f"Не найден входной JSONL: {in_path}")
    if not hier_path.exists():
        raise FileNotFoundError(f"Не найден cwe_hierarchy.json: {hier_path}")

    hierarchy = json.loads(hier_path.read_text(encoding="utf-8"))

    out_lines = []
    total = 0
    enriched = 0
    no_cwe = 0
    missing_in_hierarchy = 0

    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            total += 1
            rec = json.loads(line)

            cwe_list = rec.get("cwe") or []
            primary = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else None

            if not primary:
                no_cwe += 1
                rec["cwe_primary_id"] = None
                rec["cwe_parent_id"] = None
                rec["cwe_top_id"] = None
                rec["cwe_depth"] = None
                rec["cwe_path"] = None
                rec["cwe_is_leaf"] = None
            else:
                h = hierarchy.get(primary)
                if h:
                    enriched += 1
                    rec["cwe_primary_id"] = primary
                    rec["cwe_parent_id"] = h.get("parent_id")
                    rec["cwe_top_id"] = h.get("top_id")
                    rec["cwe_depth"] = h.get("depth")
                    rec["cwe_path"] = h.get("path")
                    rec["cwe_is_leaf"] = h.get("is_leaf")
                else:
                    missing_in_hierarchy += 1
                    rec["cwe_primary_id"] = primary
                    rec["cwe_parent_id"] = None
                    rec["cwe_top_id"] = None
                    rec["cwe_depth"] = None
                    rec["cwe_path"] = None
                    rec["cwe_is_leaf"] = None

            out_lines.append(json.dumps(rec, ensure_ascii=False))

    out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    print(f"[OK] Saved: {out_path}")
    print(f"[OK] Total rows: {total}")
    print(f"[OK] Enriched with hierarchy: {enriched}")
    print(f"[OK] No CWE: {no_cwe}")
    print(f"[OK] CWE not found in hierarchy: {missing_in_hierarchy}")


if __name__ == "__main__":
    main()