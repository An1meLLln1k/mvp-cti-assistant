from typing import Dict, Any, List, Tuple

from .prompt import build_rag_prompt
from ..llm.client import MockLLMClient


def generate_rag_answer(
    query: str,
    hits: List[Tuple[float, Dict[str, Any]]],
    fallback_answer: Dict[str, Any],
    mode: str = "mock"
) -> Dict[str, Any]:
    prompt = build_rag_prompt(query, hits)

    if mode == "mock":
        client = MockLLMClient()
        llm_json = client.generate_json(prompt, fallback_answer)
        return {
            "mode": mode,
            "prompt": prompt,
            "llm_answer": llm_json
        }

    raise ValueError(f"Unsupported LLM mode: {mode}")