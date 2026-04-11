import json
from typing import Dict, Any
from urllib import request, error

from openai import OpenAI

from ..config import (
    OPENAI_API_KEY,
    OPENAI_MODEL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
)


class MockLLMClient:
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


class OpenAILLMClient:
    def __init__(self):
        if not OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY не найден. Создай .env на основе .env.example и укажи ключ."
            )
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = OPENAI_MODEL

    def generate_json(self, prompt: str, fallback_answer: Dict[str, Any]) -> Dict[str, Any]:
        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "Ты отвечаешь строго JSON-объектом без markdown и без пояснений."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
        )

        text = response.choices[0].message.content
        if not text:
            raise ValueError("LLM вернула пустой ответ.")

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM вернула невалидный JSON: {text}") from e


class OllamaLLMClient:
    def __init__(self):
        self.base_url = OLLAMA_BASE_URL.rstrip("/")
        self.model = OLLAMA_MODEL

    def generate_json(self, prompt: str, fallback_answer: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "prompt": (
                "Ты отвечаешь строго JSON-объектом без markdown и без пояснений.\n\n"
                + prompt
            ),
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1
            }
        }

        req = request.Request(
            url=f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=180) as resp:
                raw = resp.read().decode("utf-8")
        except error.URLError as e:
            raise RuntimeError(
                "Не удалось подключиться к Ollama. Убедись, что Ollama установлен и запущен."
            ) from e

        data = json.loads(raw)
        text = data.get("response", "")

        if not text:
            raise ValueError("Ollama вернула пустой ответ.")

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Ollama вернула невалидный JSON: {text}") from e


def get_llm_client(mode: str):
    if mode == "mock":
        return MockLLMClient()
    if mode == "openai":
        return OpenAILLMClient()
    if mode == "ollama":
        return OllamaLLMClient()
    raise ValueError(f"Unsupported LLM mode: {mode}")