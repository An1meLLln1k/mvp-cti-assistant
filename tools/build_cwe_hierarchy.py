# tools/build_cwe_hierarchy.py
import json
from pathlib import Path
from xml.etree.ElementTree import iterparse
import argparse

def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag

def build_parent_map(xml_path: Path):
    parent = {}
    names = {}

    for event, elem in iterparse(xml_path, events=("end",)):
        if strip_ns(elem.tag) == "Weakness" and "ID" in elem.attrib:
            cwe_id = f"CWE-{elem.attrib['ID']}"
            names[cwe_id] = elem.attrib.get("Name")

            p = None
            for rel in elem.iter():
                if strip_ns(rel.tag) == "Related_Weakness":
                    if rel.attrib.get("Nature") == "ChildOf" and rel.attrib.get("View_ID") == "1000":
                        if rel.attrib.get("Ordinal") == "Primary":
                            p = f"CWE-{rel.attrib.get('CWE_ID')}"
                            break
                        if p is None:
                            p = f"CWE-{rel.attrib.get('CWE_ID')}"
            if p:
                parent[cwe_id] = p

            elem.clear()

    return parent, names

def compute_chain(cwe_id: str, parent_map: dict[str, str]) -> list[str]:
    chain = [cwe_id]
    seen = {cwe_id}
    while chain[-1] in parent_map:
        nxt = parent_map[chain[-1]]
        if nxt in seen:
            break
        chain.append(nxt)
        seen.add(nxt)
    return chain  # leaf -> ... -> top

def main():
    root = Path(__file__).resolve().parents[1]       # корень репо
    ds = root / "dataset"

    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", default=str(ds / "cwec_v4.19.1.xml"))
    parser.add_argument("--out", default=str(ds / "cwe_hierarchy.json"))
    args = parser.parse_args()

    xml_path = Path(args.xml)
    out_path = Path(args.out)

    print(f"[INFO] XML: {xml_path}")
    print(f"[INFO] OUT: {out_path}")

    if not xml_path.exists():
        raise FileNotFoundError(f"Не найден CWE XML: {xml_path}")

    parent_map, names = build_parent_map(xml_path)
    has_children = set(parent_map.values())

    out = {}
    for cwe_id in names.keys():
        chain = compute_chain(cwe_id, parent_map)
        top = chain[-1]
        depth = len(chain) - 1
        path_top_to_leaf = " > ".join(reversed(chain))

        out[cwe_id] = {
            "name": names.get(cwe_id),
            "parent_id": parent_map.get(cwe_id),
            "top_id": top,
            "depth": depth,
            "path": path_top_to_leaf,
            "is_leaf": cwe_id not in has_children,
        }

    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Saved: {out_path} (items={len(out)})")

if __name__ == "__main__":
    main()