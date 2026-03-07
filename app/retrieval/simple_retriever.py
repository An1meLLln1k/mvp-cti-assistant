import re
from typing import List, Dict, Any, Tuple, Set

WORD_RE = re.compile(r"[A-Za-z0-9\-_]{2,}")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

GENERIC_TOKENS = {
    "cve",
    "cwe",
    "vulnerability",
    "issue",
    "bug",
    "exploit",
    "summary",
    "details",
    "about",
    "tell",
    "what",
    "with",
    "plugin",  # слишком общий мусорный токен
}


def tokenize(text: str) -> List[str]:
    raw = [t.lower() for t in WORD_RE.findall(text or "")]
    stop = {
        "the", "and", "for", "that", "this", "from", "into", "over",
        "what", "about", "tell", "give", "short", "brief",
    }
    return [t for t in raw if t not in stop and len(t) >= 3]


def extract_cves(text: str) -> List[str]:
    return [m.group(0).upper() for m in CVE_RE.finditer(text or "")]


def score_record(q_tokens: List[str], rec: Dict[str, Any]) -> Tuple[float, Set[str]]:
    cve_id = (rec.get("cve_id") or "").lower()
    desc = (rec.get("description") or "").lower()

    score = 0.0
    matched_tokens: Set[str] = set()

    for t in q_tokens:
        if t in GENERIC_TOKENS or len(t) < 3:
            continue

        # Для не-exact режима очень общие короткие токены в cve_id не используем
        if len(t) >= 5 and t in cve_id:
            score += 6.0
            matched_tokens.add(t)
            continue

        if t in desc:
            score += 2.5 if len(t) >= 6 else 1.5
            matched_tokens.add(t)

    if len(matched_tokens) >= 2:
        score += 1.0

    return score, matched_tokens


def retrieve(query: str, records: List[Dict[str, Any]], top_k: int = 3) -> List[Tuple[float, Dict[str, Any]]]:
    query_cves = extract_cves(query)

    # 1) Если в запросе есть нормальный CVE-ID -> только exact match
    if query_cves:
        exact_hits = []
        qset = set(query_cves)

        for rec in records:
            rid = (rec.get("cve_id") or "").upper()
            if rid in qset:
                exact_hits.append((100.0, rec))

        return exact_hits[:top_k]

    # 2) Иначе текстовый retrieval
    q_tokens = tokenize(query)
    q_tokens = [t for t in q_tokens if t not in GENERIC_TOKENS]

    if not q_tokens:
        return []

    ranked: List[Tuple[float, int, Dict[str, Any]]] = []

    for rec in records:
        score, matched = score_record(q_tokens, rec)
        if score > 0:
            ranked.append((score, len(matched), rec))

    if not ranked:
        return []

    ranked.sort(key=lambda x: (x[0], x[1]), reverse=True)
    best_score = ranked[0][0]

    # Чем длиннее запрос, тем строже требуем покрытие токенов
    if len(q_tokens) == 1:
        min_required = 1
    elif len(q_tokens) <= 3:
        min_required = 2
    else:
        min_required = 3

    filtered: List[Tuple[float, Dict[str, Any]]] = []

    for score, matched_count, rec in ranked:
        coverage = matched_count / max(1, len(q_tokens))

        if score < 2.5:
            continue
        if matched_count < min_required:
            continue
        if coverage < 0.6:
            continue
        if score < best_score * 0.45:
            continue

        filtered.append((score, rec))

    return filtered[:top_k]