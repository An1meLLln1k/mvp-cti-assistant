import re
from typing import List, Dict, Any, Tuple

_word = re.compile(r"[A-Za-z0-9\-_]{2,}")

def tokenize(text: str) -> List[str]:
    return [t.lower() for t in _word.findall(text or "")]

def score_record(q_tokens: List[str], rec: Dict[str, Any]) -> float:
    cve_id = (rec.get("cve_id") or "").lower()
    desc = (rec.get("description") or "").lower()

    score = 0.0
    for t in q_tokens:
        if t in cve_id:
            score += 5.0
        if t in desc:
            score += 1.0

    # небольшой бонус, если в запросе есть "cve-" и запись вообще CVE
    if "cve" in q_tokens and cve_id.startswith("cve-"):
        score += 1.0

    return score

def retrieve(query: str, records: List[Dict[str, Any]], top_k: int = 3) -> List[Tuple[float, Dict[str, Any]]]:
    q_tokens = tokenize(query)
    scored = []
    for rec in records:
        s = score_record(q_tokens, rec)
        if s > 0:
            scored.append((s, rec))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[:top_k]