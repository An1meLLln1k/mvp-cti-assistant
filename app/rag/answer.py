from typing import Dict, Any, List, Tuple, Optional


def _build_item(score: float, rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
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
    }


def build_answer(
    query: str,
    hits: List[Tuple[float, Dict[str, Any]]],
    suggested_cve: Optional[str] = None,
) -> Dict[str, Any]:
    if not hits:
        summary = "По запросу не найден релевантный контекст в локальном корпусе."
        actions: List[str] = []

        if suggested_cve:
            summary = (
                f"Точный идентификатор уязвимости не найден. "
                f"Возможно, имелся в виду: {suggested_cve}."
            )
            actions = ["Проверить корректность введённого CVE-ID и повторить запрос."]

        return {
            "query": query,
            "status": "no_hits",
            "summary": summary,
            "actions": actions,
            "items": [],
            "suggested_cve": suggested_cve,
        }

    items = [_build_item(score, rec) for score, rec in hits]
    has_kev = any(item.get("kev") is True for item in items)

    actions = [
        "Проверить наличие патча или обновления у вендора.",
        "Определить, используется ли уязвимый компонент в вашей инфраструктуре.",
    ]

    if has_kev:
        actions.append("Если уязвимость входит в KEV, повысить приоритет устранения.")
    else:
        actions.append("Оценить внешнюю доступность уязвимого сервиса до устранения проблемы.")

    top = items[0]
    top_cve = top.get("cve_id")

    if len(items) == 1 and top_cve:
        summary = f"Найден 1 релевантный кандидат: {top_cve}. Retrieval-only baseline без генерации."
    else:
        summary = f"Найдено {len(items)} релевантных кандидатов. Retrieval-only baseline без генерации."

    return {
        "query": query,
        "status": "ok",
        "summary": summary,
        "actions": actions,
        "items": items,
        "suggested_cve": None,
    }