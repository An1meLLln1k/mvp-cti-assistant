from typing import Dict, Any, List, Tuple

def build_answer(query: str, hits: List[Tuple[float, Dict[str, Any]]]) -> Dict[str, Any]:
    if not hits:
        return {
            "query": query,
            "status": "no_hits",
            "summary": "Ничего релевантного в локальном корпусе не нашёл.",
            "items": [],
        }

    items = []
    for score, rec in hits:
        items.append({
            "cve_id": rec.get("cve_id"),
            "score": score,
            "description": rec.get("description"),
            "published_date": rec.get("published_date"),
            "kev": (rec.get("source") == "KEV") or bool(rec.get("kev")),
            "cwe": {
                "primary": rec.get("cwe_primary_id"),
                "top": rec.get("cwe_top_id"),
                "parent": rec.get("cwe_parent_id"),
                "depth": rec.get("cwe_depth"),
                "path": rec.get("cwe_path"),
                "is_leaf": rec.get("cwe_is_leaf"),
            },
            "references": rec.get("references") or [],
        })

    actions = [
        "Проверь патч/обновление у вендора и поставь приоритет обновлению.",
        "Проверь экспонирование: где компонент используется, есть ли доступ извне.",
        "Если в KEV: ставь в топ и делай компенсирующие меры (WAF/изоляция/отключение вектора).",
    ]

    return {
        "query": query,
        "status": "ok",
        "summary": f"Найдено {len(items)} кандидатов. Пока без LLM, чисто MVP-контур.",
        "actions": actions,
        "items": items,
    }