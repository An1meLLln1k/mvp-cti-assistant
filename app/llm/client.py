import json
from typing import Dict, Any


class MockLLMClient:
    """
    Временный mock-клиент.
    Нужен, чтобы замкнуть RAG-контур до подключения реальной LLM.
    """

    def generate_json(self, prompt: str, fallback_answer: Dict[str, Any]) -> Dict[str, Any]:
        items = fallback_answer.get("items", [])

        if not items:
            return {
                "summary": "Недостаточно контекста для уверенного ответа.",
                "actions": [
                    "Уточнить запрос.",
                    "Проверить наличие релевантного CVE в корпусе.",
                    "При необходимости расширить retrieval-контекст."
                ],
                "kev": False,
                "cwe": {
                    "primary": None,
                    "top": None
                },
                "references": [],
                "grounded": False,
                "notes": "Mock LLM: retrieval не вернул релевантный контекст."
            }

        top = items[0]
        refs = top.get("references") or []

        return {
            "summary": top.get("description"),
            "actions": [
                "Проверить наличие патча/обновления у вендора.",
                "Оценить экспонирование уязвимого компонента во внешнюю сеть.",
                "Если CVE присутствует в KEV, повысить приоритет remediation."
            ],
            "kev": bool(top.get("kev")),
            "cwe": {
                "primary": top.get("cwe", {}).get("primary"),
                "top": top.get("cwe", {}).get("top")
            },
            "references": refs[:5],
            "grounded": True,
            "notes": "Mock LLM: ответ собран из retrieval-контекста без вызова внешней модели."
        }