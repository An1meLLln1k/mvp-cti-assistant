import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import csv
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

RAW_NVD_DIR = ROOT / "dataset" / "raw" / "nvd"
RAW_KEV_PATH = ROOT / "dataset" / "raw" / "kev" / "known_exploited_vulnerabilities.csv"
OUT_PATH = ROOT / "dataset" / "dataset_v2.jsonl"


def load_kev_csv(path: Path) -> Dict[str, Dict[str, Any]]:
    kev_map: Dict[str, Dict[str, Any]] = {}

    if not path.exists():
        print(f"[WARN] KEV CSV not found: {path}")
        return kev_map

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = (row.get("cveID") or row.get("cveId") or row.get("CVE") or "").strip().upper()
            if not cve_id:
                continue

            kev_map[cve_id] = {
                "kev": True,
                "kev_vendor_project": row.get("vendorProject"),
                "kev_product": row.get("product"),
                "kev_date_added": row.get("dateAdded"),
                "kev_due_date": row.get("dueDate"),
                "kev_required_action": row.get("requiredAction"),
                "kev_notes": row.get("notes"),
                "kev_ransomware_use": row.get("knownRansomwareCampaignUse"),
            }

    print(f"[OK] Loaded KEV entries: {len(kev_map)}")
    return kev_map


def safe_get_description(cve_item: Dict[str, Any]) -> Optional[str]:
    descriptions = cve_item.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    if descriptions:
        return descriptions[0].get("value")
    return None


def safe_get_references(cve_item: Dict[str, Any]) -> List[str]:
    refs = []
    for r in cve_item.get("references", []):
        url = r.get("url")
        if url:
            refs.append(url)
    return refs


def safe_get_cwe(cve_item: Dict[str, Any]) -> List[str]:
    result = []

    weaknesses = cve_item.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            value = (desc.get("value") or "").strip()
            if value.startswith("CWE-") and value not in result:
                result.append(value)

    return result


def safe_get_cvss_v31(metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss = m.get("cvssData", {})
            return {
                "source": key,
                "base_score": cvss.get("baseScore"),
                "base_severity": cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString"),
                "attack_vector": cvss.get("attackVector"),
                "attack_complexity": cvss.get("attackComplexity"),
                "privileges_required": cvss.get("privilegesRequired"),
                "user_interaction": cvss.get("userInteraction"),
                "scope": cvss.get("scope"),
                "confidentiality_impact": cvss.get("confidentialityImpact"),
                "integrity_impact": cvss.get("integrityImpact"),
                "availability_impact": cvss.get("availabilityImpact"),
            }
    return None


def parse_nvd_file(path: Path, kev_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    print(f"[INFO] Parsing NVD file: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))

    vulnerabilities = data.get("vulnerabilities", [])
    rows: List[Dict[str, Any]] = []

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = (cve.get("id") or "").strip().upper()
        if not cve_id:
            continue

        metrics = cve.get("metrics", {})
        cvss = safe_get_cvss_v31(metrics)
        cwe_list = safe_get_cwe(cve)
        references = safe_get_references(cve)
        description = safe_get_description(cve)

        row: Dict[str, Any] = {
            "cve_id": cve_id,
            "source": "NVD",
            "published_date": cve.get("published"),
            "last_modified_date": cve.get("lastModified"),
            "description": description,
            "cwe": cwe_list,
            "references": references,
            "cvss": cvss,
            "kev": False,
        }

        if cve_id in kev_map:
            row.update(kev_map[cve_id])

        rows.append(row)

    print(f"[OK] Parsed rows from {path.name}: {len(rows)}")
    return rows


def main() -> None:
    nvd_files = sorted(RAW_NVD_DIR.glob("*.json"))

    if not nvd_files:
        raise FileNotFoundError(
            f"Нет NVD JSON файлов в {RAW_NVD_DIR}. "
            f"Положи туда хотя бы один файл вида nvdcve-2.0-2024.json"
        )

    kev_map = load_kev_csv(RAW_KEV_PATH)

    all_rows: List[Dict[str, Any]] = []
    seen = set()

    for nvd_file in nvd_files:
        rows = parse_nvd_file(nvd_file, kev_map)
        for row in rows:
            cve_id = row["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            all_rows.append(row)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as f:
        for row in all_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] Saved dataset_v2: {OUT_PATH}")
    print(f"[OK] Total rows: {len(all_rows)}")
    print(f"[OK] Build time: {datetime.now().isoformat(timespec='seconds')}")


if __name__ == "__main__":
    main()