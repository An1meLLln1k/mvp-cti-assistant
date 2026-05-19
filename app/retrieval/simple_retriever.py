import difflib
import re
from typing import List, Dict, Any, Tuple, Set, Optional

WORD_RE = re.compile(r"[A-Za-z0-9\-_]{2,}")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVE_LIKE_RE = re.compile(r"\bCVE-\d{4}-[A-Za-z0-9]{3,8}\b", re.IGNORECASE)

GENERIC_TOKENS = {
    "cve", "cwe", "vulnerability", "issue", "bug", "exploit",
    "summary", "details", "about", "tell", "what", "with",
    "plugin", "старом", "старый", "уязвимость", "известно",
    "расскажи", "что", "это", "за", "дай", "краткое", "резюме",
    "браузере", "browser", "через", "про", "для", "при", "или",
    "как", "по", "page", "html"
}

ALIASES = {
    "chromium": ["chromium", "chrome", "google chrome"],
    "chrome": ["chrome", "chromium", "google chrome"],
    "браузер": ["browser", "chrome", "chromium"],
    "браузере": ["browser", "chrome", "chromium"],
    "css": ["css"],
    "heap": ["heap", "corruption"],
    "corruption": ["corruption", "heap"],
    "sql": ["sql", "injection", "sql injection"],
    "injection": ["injection", "sql", "sql injection"],
    "wordpress": ["wordpress"],
    "oracle": ["oracle"],
    "weblogic": ["weblogic"],
    "deserialization": ["deserialization"],
    "rce": ["rce", "remote code execution"],
    "remote": ["remote"],
    "crafted": ["crafted"],
    "use-after-free": ["use-after-free", "use after free", "uaf"],
    "uaf": ["uaf", "use after free", "use-after-free"],
}

ANCHOR_GROUPS = {
    "chromium": {"chromium", "chrome", "google chrome"},
    "chrome": {"chromium", "chrome", "google chrome"},
    "wordpress": {"wordpress"},
    "oracle": {"oracle"},
    "weblogic": {"weblogic", "oracle"},
    "beyondtrust": {"beyondtrust"},
}

PHRASE_ALIASES = {
    "use-after-free": ["use-after-free", "use after free", "uaf"],
    "use after free": ["use-after-free", "use after free", "uaf"],
    "heap corruption": ["heap corruption"],
    "crafted html page": ["crafted html page", "crafted html"],
    "sql injection": ["sql injection"],
    "remote deserialization": ["remote deserialization", "deserialization"],
    "remote code execution": ["remote code execution", "rce"],
}


def normalize_text(text: str) -> str:
    text = (text or "").lower()
    text = text.replace("-", " ")
    text = text.replace("_", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def tokenize(text: str) -> List[str]:
    raw = [t.lower() for t in WORD_RE.findall(text or "")]
    return [t for t in raw if len(t) >= 3]


def extract_cves(text: str) -> List[str]:
    return [m.group(0).upper() for m in CVE_RE.finditer(text or "")]


def extract_cve_like(text: str) -> List[str]:
    return [m.group(0).upper() for m in CVE_LIKE_RE.finditer(text or "")]


def suggest_similar_cve(query: str, records: List[Dict[str, Any]]) -> Optional[str]:
    strict = extract_cves(query)
    loose = extract_cve_like(query)

    needle = strict[0] if strict else (loose[0] if loose else "")
    if not needle:
        return None

    all_cves = sorted(
        {
            (rec.get("cve_id") or "").upper()
            for rec in records
            if rec.get("cve_id")
        }
    )

    if needle in all_cves:
        return None

    parts = needle.split("-")
    if len(parts) < 3:
        return None

    year = parts[1]
    suffix = parts[2]

    # Совсем короткий хвост не подсказываем
    if len(suffix) < 3:
        return None

    same_year_pool = [c for c in all_cves if c.startswith(f"CVE-{year}-")]
    if not same_year_pool:
        return None

    prefix_matches = []
    for cve in same_year_pool:
        cve_parts = cve.split("-")
        if len(cve_parts) >= 3:
            candidate_suffix = cve_parts[2]
            if candidate_suffix.startswith(suffix):
                prefix_matches.append(cve)

    # Подсказку даём только если кандидат ровно один
    if len(prefix_matches) == 1:
        return prefix_matches[0]

    return None

def expand_tokens(tokens: List[str]) -> List[str]:
    expanded = []
    for t in tokens:
        expanded.append(t)
        if t in ALIASES:
            expanded.extend(ALIASES[t])

    seen = set()
    result = []
    for t in expanded:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def extract_query_phrases(query: str) -> List[str]:
    q_norm = normalize_text(query)
    phrases = []

    for base, variants in PHRASE_ALIASES.items():
        for variant in variants:
            if normalize_text(variant) in q_norm:
                phrases.append(normalize_text(base))
                break

    if all(x in q_norm for x in ["use", "after", "free"]) and "use after free" not in phrases:
        phrases.append("use after free")

    return phrases


def extract_anchor_terms(query: str) -> Set[str]:
    q_norm = normalize_text(query)
    anchors = set()

    for anchor, variants in ANCHOR_GROUPS.items():
        for v in variants:
            if normalize_text(v) in q_norm:
                anchors.add(anchor)
                break

    return anchors


def build_search_text(rec: Dict[str, Any]) -> str:
    parts = [
        rec.get("cve_id") or "",
        rec.get("description") or "",
        " ".join(rec.get("cwe") or []),
        " ".join(rec.get("references") or []),
        rec.get("kev_vendor_project") or "",
        rec.get("kev_product") or "",
        rec.get("kev_required_action") or "",
        rec.get("kev_notes") or "",
    ]

    cvss = rec.get("cvss") or {}
    if isinstance(cvss, dict):
        parts.extend([
            str(cvss.get("base_severity") or ""),
            str(cvss.get("vector") or ""),
            str(cvss.get("attack_vector") or ""),
        ])

    return normalize_text(" ".join(parts))


def match_anchor(anchor: str, search_text: str) -> bool:
    variants = ANCHOR_GROUPS.get(anchor, {anchor})
    return any(normalize_text(v) in search_text for v in variants)


def score_record(
    q_tokens: List[str],
    q_phrases: List[str],
    q_anchors: Set[str],
    rec: Dict[str, Any]
) -> Tuple[float, Set[str], Set[str]]:
    search_text = build_search_text(rec)

    if q_anchors:
        if not any(match_anchor(anchor, search_text) for anchor in q_anchors):
            return 0.0, set(), set()

    score = 0.0
    matched_tokens: Set[str] = set()
    matched_phrases: Set[str] = set()

    for phrase in q_phrases:
        if normalize_text(phrase) in search_text:
            matched_phrases.add(phrase)
            if phrase == "use after free":
                score += 6.0
            elif phrase == "heap corruption":
                score += 4.0
            elif phrase == "crafted html page":
                score += 4.0
            elif phrase == "sql injection":
                score += 4.0
            else:
                score += 3.0

    for t in q_tokens:
        t_norm = normalize_text(t)
        if t_norm in GENERIC_TOKENS or len(t_norm) < 3:
            continue

        if t_norm in search_text:
            if t_norm in {"chromium", "chrome", "css", "heap", "corruption", "wordpress", "oracle", "weblogic"}:
                score += 2.8
            elif t_norm in {"sql", "injection", "deserialization", "crafted"}:
                score += 2.2
            else:
                score += 1.2
            matched_tokens.add(t_norm)

    if len(matched_tokens) >= 2:
        score += 1.5
    if len(matched_tokens) >= 3:
        score += 2.0
    if matched_phrases:
        score += 1.5 * len(matched_phrases)

    if rec.get("kev") is True:
        score += 0.5

    return score, matched_tokens, matched_phrases


def retrieve(query: str, records: List[Dict[str, Any]], top_k: int = 3) -> List[Tuple[float, Dict[str, Any]]]:
    query_cves = extract_cves(query)

    if query_cves:
        exact_hits = []
        qset = set(query_cves)
        for rec in records:
            rid = (rec.get("cve_id") or "").upper()
            if rid in qset:
                exact_hits.append((100.0, rec))
        return exact_hits[:top_k]

    q_tokens = [t for t in tokenize(query) if t.lower() not in GENERIC_TOKENS]
    q_tokens = expand_tokens(q_tokens)
    q_phrases = extract_query_phrases(query)
    q_anchors = extract_anchor_terms(query)

    if not q_tokens and not q_phrases:
        return []

    ranked: List[Tuple[float, int, int, Dict[str, Any]]] = []

    for rec in records:
        score, matched_tokens, matched_phrases = score_record(q_tokens, q_phrases, q_anchors, rec)
        if score > 0:
            ranked.append((score, len(matched_tokens), len(matched_phrases), rec))

    if not ranked:
        return []

    ranked.sort(key=lambda x: (x[0], x[2], x[1]), reverse=True)
    best_score = ranked[0][0]

    filtered: List[Tuple[float, Dict[str, Any]]] = []

    for score, matched_count, matched_phrase_count, rec in ranked:
        unique_query_units = max(1, len(set(q_tokens)) + len(set(q_phrases)))
        covered_units = matched_count + matched_phrase_count
        coverage = covered_units / unique_query_units

        if score < 3.0:
            continue
        if covered_units < 2:
            continue
        if coverage < 0.28:
            continue
        if score < best_score * 0.55:
            continue

        filtered.append((score, rec))

    return filtered[:top_k]