from typing import List, Tuple, Dict, Any


def format_context_item(score: float, rec: Dict[str, Any]) -> str:
    cve_id = rec.get("cve_id")
    description = rec.get("description")
    published_date = rec.get("published_date")
    kev = rec.get("kev")
    cwe_primary = rec.get("cwe_primary_id")
    cwe_top = rec.get("cwe_top_id")
    cwe_path = rec.get("cwe_path")
    references = rec.get("references") or []

    refs_text = "\n".join(f"- {r}" for r in references[:5]) if references else "- none"

    return f"""[DOCUMENT]
score: {score:.3f}
cve_id: {cve_id}
published_date: {published_date}
kev: {kev}
cwe_primary_id: {cwe_primary}
cwe_top_id: {cwe_top}
cwe_path: {cwe_path}
description: {description}
references:
{refs_text}
[/DOCUMENT]"""


def build_context(hits: List[Tuple[float, Dict[str, Any]]]) -> str:
    if not hits:
        return "[NO_CONTEXT]"
    return "\n\n".join(format_context_item(score, rec) for score, rec in hits)


def build_rag_prompt(query: str, hits: List[Tuple[float, Dict[str, Any]]]) -> str:
    context = build_context(hits)

    prompt = f"""Ты — интеллектуальный ассистент для анализа киберугроз.

Тебе дан запрос пользователя и найденный retrieval-контекст.
Отвечай только на основе найденного контекста.
Если контекста недостаточно, так и скажи.
Не выдумывай CVE, CWE, ссылки или факты, которых нет в контексте.

Запрос пользователя:
{query}

Контекст:
{context}

Верни ответ строго в JSON-формате со следующими полями:
{{
  "summary": "краткое резюме по найденной уязвимости или набору кандидатов",
  "actions": ["рекомендация 1", "рекомендация 2", "рекомендация 3"],
  "kev": true,
  "cwe": {{
    "primary": "CWE-...",
    "top": "CWE-..."
  }},
  "references": ["url1", "url2"],
  "grounded": true,
  "notes": "если контекста мало или есть неоднозначность — напиши это здесь"
}}

Важно:
- summary должен быть кратким и по делу;
- actions должны быть практическими;
- references брать только из контекста;
- если точного ответа нет, это нужно явно указать в notes.
"""
    return prompt