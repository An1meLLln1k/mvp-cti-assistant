# tools/enrich_dataset_with_cwe.py
import json
from pathlib import Path
import argparse

def main():
    root = Path(__file__).resolve().parents[1]
    ds = root / "dataset"

    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", default=str(ds / "dataset_v0.jsonl"))
    parser.add_argument("--hier", default=str(ds / "cwe_hierarchy.json"))
    parser.add_argument("--out", default=str(ds / "dataset_v1.jsonl"))
    args = parser.parse_args()

    in_path = Path(args.in_path)
    hier_path = Path(args.hier)
    out_path = Path(args.out)

    # если ты назвал файл иначе, попробуем dataset.jsonl
    if not in_path.exists():
        alt = ds / "dataset.jsonl"
        if alt.exists():
            in_path = alt

    print(f"[INFO] IN:   {in_path}")
    print(f"[INFO] HIER: {hier_path}")
    print(f"[INFO] OUT:  {out_path}")

    if not in_path.exists():
        raise FileNotFoundError(f"Не найден входной JSONL: {in_path}")
    if not hier_path.exists():
        raise FileNotFoundError(f"Не найден cwe_hierarchy.json: {hier_path} (сначала запусти build_cwe_hierarchy.py)")

    hierarchy = json.loads(hier_path.read_text(encoding="utf-8"))

    out_lines = []
    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)

            cwe_list = rec.get("cwe") or []
            primary = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else None
            h = hierarchy.get(primary) if primary else None

            rec["cwe_primary_id"] = primary
            rec["cwe_parent_id"] = h.get("parent_id") if h else None
            rec["cwe_top_id"] = h.get("top_id") if h else None
            rec["cwe_depth"] = h.get("depth") if h else None
            rec["cwe_path"] = h.get("path") if h else None
            rec["cwe_is_leaf"] = h.get("is_leaf") if h else None

            out_lines.append(json.dumps(rec, ensure_ascii=False))

    out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"[OK] Saved: {out_path} (rows={len(out_lines)})")

if __name__ == "__main__":
    main()