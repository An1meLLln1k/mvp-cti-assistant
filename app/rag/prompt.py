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

    if context == "[NO_CONTEXT]":
        return f"""Ты — интеллектуальный ассистент для первичного анализа уязвимостей.

Тебе даны:
1) запрос пользователя;
2) retrieval-контекст из локального корпуса.

Запрос пользователя:
{query}

Контекст:
[NO_CONTEXT]

Критически важное правило:
В локальном корпусе не найден релевантный контекст.
Значит, ты не должен:
- выдумывать факты;
- придумывать рекомендации по конкретной уязвимости;
- придумывать CWE;
- придумывать ссылки;
- делать вид, что знаешь ответ.

Верни строго JSON-объект такого вида:
{{
  "summary": "По запросу не найден релевантный контекст в локальном корпусе.",
  "actions": [],
  "kev": false,
  "cwe": {{
    "primary": null,
    "top": null
  }},
  "references": [],
  "grounded": false,
  "notes": "В локальном корпусе не найдено подтверждённого релевантного контекста по запросу."
}}

Дополнительные требования:
- Пиши строго на русском языке.
- Не добавляй никаких пояснений вне JSON.
- Не добавляй служебных комментариев.
- Не заполняй actions, references и cwe никакими значениями.
"""

    return f"""Ты — интеллектуальный ассистент для первичного анализа уязвимостей.

Тебе даны:
1) запрос пользователя;
2) retrieval-контекст из локального корпуса.

Правила:
- Отвечай только на основе контекста ниже.
- Ничего не выдумывай.
- Не добавляй общие советы, если их нет в контексте.
- Не упоминай антивирус, безопасные протоколы, шифрование, аутентификацию пользователей и другие общие меры, если они не следуют напрямую из контекста.
- Пиши строго на русском языке.
- Идентификаторы CVE, CWE и URL не переводить.
- В поле cwe.top указывай только верхний CWE-идентификатор, например "CWE-707".
- Не записывай в cwe.top полный путь вида "CWE-707 > CWE-74 > ...".
- Если контекста недостаточно, честно укажи это в notes.
- Не пиши в notes технические комментарии про нормализацию, генерацию или внутреннюю обработку.
- Если данных в контексте мало, не додумывай детали, а формулируй ответ консервативно.

Запрос пользователя:
{query}

Контекст:
{context}

Верни строго JSON-объект такого вида:
{{
  "summary": "1-2 предложения по сути уязвимости",
  "actions": [
    "конкретное действие 1",
    "конкретное действие 2",
    "конкретное действие 3"
  ],
  "kev": true,
  "cwe": {{
    "primary": "CWE-...",
    "top": "CWE-..."
  }},
  "references": ["url1", "url2"],
  "grounded": true,
  "notes": "краткая пометка, если данных мало или есть неоднозначность"
}}

Требования:
- summary: кратко и по делу;
- actions: только практические и уместные действия;
- references: брать только из контекста;
- grounded=true только если ответ реально опирается на контекст;
- notes не должны быть служебной отпиской и не должны дублировать summary дословно.
"""