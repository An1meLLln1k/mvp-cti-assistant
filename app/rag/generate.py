from typing import Dict, Any, List, Tuple
import re

from .prompt import build_rag_prompt
from ..llm.client import get_llm_client


CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        key = value.strip()
        if not key:
            continue
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result

def _normalize_free_text(text: str) -> str:
    text = (text or "").lower().strip()
    text = re.sub(r"https?://\S+", "", text)
    text = text.replace("ё", "е")
    text = re.sub(r"[^a-zа-я0-9\s-]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _looks_like_summary_duplicate(notes: str, summary: str) -> bool:
    n = _normalize_free_text(notes)
    s = _normalize_free_text(summary)

    if not n or not s:
        return False

    if n == s:
        return True

    if len(n) >= 24 and n in s:
        return True

    if len(s) >= 24 and s in n:
        return True

    n_tokens = set(n.split())
    s_tokens = set(s.split())

    if not n_tokens or not s_tokens:
        return False

    overlap = len(n_tokens & s_tokens) / max(1, min(len(n_tokens), len(s_tokens)))
    return overlap >= 0.8


def _is_action_too_generic(text: str) -> bool:
    lower = _normalize_free_text(text)

    generic_phrases = [
        "обновить все установленные пакеты безопасности",
        "использовать только проверенные и обновленные версии",
        "использовать только проверенные и обновлённые версии",
        "использовать только обновленные версии",
        "использовать только обновлённые версии",
        "установить последние обновления безопасности",
        "повысить уровень безопасности",
        "принять меры безопасности",
        "использовать защищенные протоколы",
        "использовать защищённые протоколы",
        "обновить все установленные версии",
        "обновить все пакеты",
        "обновить все компоненты",
    ]

    generic_starts = [
        "обновить все",
        "использовать только",
        "следует использовать",
        "рекомендуется использовать",
        "необходимо использовать",
        "необходимо обновить все",
    ]

    if any(phrase in lower for phrase in generic_phrases):
        return True

    if any(lower.startswith(prefix) for prefix in generic_starts):
        return True

    return False

def _has_hits(fallback_answer: Dict[str, Any]) -> bool:
    items = fallback_answer.get("items", [])
    return isinstance(items, list) and len(items) > 0


def _get_top_item(fallback_answer: Dict[str, Any]) -> Dict[str, Any]:
    items = fallback_answer.get("items", [])
    if isinstance(items, list) and items:
        top = items[0]
        if isinstance(top, dict):
            return top
    return {}


def _extract_fallback_actions(top: Dict[str, Any], fallback_kev: bool) -> List[str]:
    actions = [
        "Проверить наличие патча или обновления у вендора.",
        "Определить, используется ли уязвимый компонент в вашей инфраструктуре.",
        "Ограничить внешнюю доступность уязвимого сервиса до устранения проблемы.",
    ]

    if fallback_kev:
        actions.insert(0, "Повысить приоритет устранения, так как уязвимость входит в каталог KEV.")

    if _is_nonempty_string(top.get("cve_id")):
        actions.append("Проверить внутренние активы и инвентаризацию на наличие данной CVE.")

    return actions[:4]


def _clean_actions(raw_actions: Any, fallback_actions: List[str], has_hits: bool) -> List[str]:
    banned_substrings = [
        "антивирус",
        "протокол",
        "шифрован",
        "аутентифика",
        "пользовател",
        "безопасные протоколы",
        "обучите пользователей",
        "смените пароль",
        "используйте vpn",
        "проведите аудит безопасности",
        "усильте мониторинг",
    ]

    generic_bad_starts = [
        "обеспечить безопасность",
        "повысить безопасность",
        "улучшить безопасность",
        "принять меры безопасности",
    ]

    cleaned: List[str] = []

    if isinstance(raw_actions, list) and has_hits:
        for item in raw_actions:
            text = _safe_str(item)
            if not text:
                continue

            lower = text.lower()

            if len(text) < 12:
                continue
            if any(bad in lower for bad in banned_substrings):
                continue
            if any(lower.startswith(prefix) for prefix in generic_bad_starts):
                continue
            if _is_action_too_generic(text):
                continue

            cleaned.append(text)

    cleaned = _dedupe_keep_order(cleaned)

    # Убираем почти одинаковые формулировки действий
    final_actions: List[str] = []
    for action in cleaned:
        norm_action = _normalize_free_text(action)
        is_duplicate = False
        for existing in final_actions:
            norm_existing = _normalize_free_text(existing)
            if norm_action == norm_existing:
                is_duplicate = True
                break
            if len(norm_action) >= 20 and norm_action in norm_existing:
                is_duplicate = True
                break
            if len(norm_existing) >= 20 and norm_existing in norm_action:
                is_duplicate = True
                break
        if not is_duplicate:
            final_actions.append(action)

    for action in fallback_actions:
        if len(final_actions) >= 3:
            break
        if _is_action_too_generic(action):
            continue
        if action not in final_actions:
            final_actions.append(action)

    return final_actions[:3]


def _normalize_cwe_value(value: Any) -> str | None:
    text = _safe_str(value).upper()
    if CWE_RE.match(text):
        return text
    return None


def _normalize_cwe(top_llm: Any, fallback_cwe: Dict[str, Any], has_hits: bool) -> Dict[str, Any]:
    llm_cwe = top_llm if isinstance(top_llm, dict) else {}

    primary = _normalize_cwe_value(llm_cwe.get("primary")) or _normalize_cwe_value(fallback_cwe.get("primary"))
    top = _normalize_cwe_value(llm_cwe.get("top")) or _normalize_cwe_value(fallback_cwe.get("top"))

    if not has_hits:
        return {
            "primary": None,
            "top": None,
        }

    return {
        "primary": primary,
        "top": top,
    }


def _normalize_references(raw_references: Any, fallback_refs: List[str], has_hits: bool) -> List[str]:
    refs: List[str] = []

    if isinstance(raw_references, list) and has_hits:
        for item in raw_references:
            text = _safe_str(item)
            if not text:
                continue
            refs.append(text)

    refs = _dedupe_keep_order(refs)

    if not refs and has_hits:
        refs = _dedupe_keep_order([_safe_str(x) for x in fallback_refs])

    return refs[:5]


def _normalize_summary(raw_summary: Any, top: Dict[str, Any], has_hits: bool) -> str:
    if not has_hits:
        return "По запросу не найден релевантный контекст в локальном корпусе."

    summary = _safe_str(raw_summary)

    if summary:
        return summary

    for key in ("description", "summary", "text"):
        value = _safe_str(top.get(key))
        if value:
            return value

    cve_id = _safe_str(top.get("cve_id"))
    if cve_id:
        return f"Найдена информация по {cve_id}, но модель не сформировала содержательное резюме."

    return "Найден релевантный контекст, но модель не сформировала содержательное резюме."


def _normalize_grounded(raw_grounded: Any, has_hits: bool) -> bool:
    if not has_hits:
        return False
    if isinstance(raw_grounded, bool):
        return raw_grounded
    return True


def _normalize_kev(raw_kev: Any, fallback_kev: bool, has_hits: bool) -> bool:
    if not has_hits:
        return False
    if isinstance(raw_kev, bool):
        return raw_kev
    return fallback_kev


def _normalize_notes(
    raw_notes: Any,
    has_hits: bool,
    grounded: bool,
    raw_llm_json: Dict[str, Any],
    summary: str,
) -> str:
    if not has_hits:
        return (
            "Это no-hit сценарий: в локальном корпусе не найдено подтверждённого "
            "релевантного контекста, поэтому ответ не должен интерпретироваться "
            "как подтверждённая информация по конкретной уязвимости."
        )

    notes = _safe_str(raw_notes)

    banned_substrings = [
        "ответ нормализован",
        "локальной llm",
        "внутренней обработке",
        "нормализац",
        "json",
        "сгенерирован",
        "служеб",
    ]

    if notes and any(bad in notes.lower() for bad in banned_substrings):
        notes = ""

    if notes and _looks_like_summary_duplicate(notes, summary):
        notes = ""

    if notes:
        return notes

    if grounded:
        return "Ответ сформирован на основе найденного локального контекста; детализация ограничена качеством локальной модели."

    if isinstance(raw_llm_json, dict) and raw_llm_json:
        return "Модель вернула частично неполный или спорный ответ, поэтому применена консервативная нормализация."

    return "Ответ собран в консервативном режиме на основе retrieval-контекста."    


def normalize_llm_answer(llm_json: Dict[str, Any], fallback_answer: Dict[str, Any]) -> Dict[str, Any]:
    has_hits = _has_hits(fallback_answer)
    top = _get_top_item(fallback_answer)

    fallback_refs = top.get("references") if isinstance(top.get("references"), list) else []
    fallback_cwe = top.get("cwe") if isinstance(top.get("cwe"), dict) else {}
    fallback_kev = bool(top.get("kev"))

    fallback_actions = _extract_fallback_actions(top, fallback_kev)

    summary = _normalize_summary(llm_json.get("summary"), top, has_hits)
    grounded = _normalize_grounded(llm_json.get("grounded"), has_hits)
    kev = _normalize_kev(llm_json.get("kev"), fallback_kev, has_hits)
    cwe = _normalize_cwe(llm_json.get("cwe"), fallback_cwe, has_hits)
    references = _normalize_references(llm_json.get("references"), fallback_refs, has_hits)
    actions = _clean_actions(llm_json.get("actions"), fallback_actions, has_hits)
    notes = _normalize_notes(llm_json.get("notes"), has_hits, grounded, llm_json, summary)

    if not has_hits:
        actions = []
        references = []
        kev = False
        cwe = {"primary": None, "top": None}
        grounded = False

    return {
        "summary": summary,
        "actions": actions,
        "kev": kev,
        "cwe": cwe,
        "references": references,
        "grounded": grounded,
        "notes": notes,
    }


def generate_rag_answer(
    query: str,
    hits: List[Tuple[float, Dict[str, Any]]],
    fallback_answer: Dict[str, Any],
    mode: str = "mock",
) -> Dict[str, Any]:
    prompt = build_rag_prompt(query, hits)
    client = get_llm_client(mode)

    raw_llm_json: Dict[str, Any] = {}
    llm_error = None

    try:
        candidate = client.generate_json(prompt, fallback_answer)
        if isinstance(candidate, dict):
            raw_llm_json = candidate
        else:
            llm_error = f"LLM returned non-dict payload: {type(candidate).__name__}"
            raw_llm_json = {}
    except Exception as exc:
        llm_error = f"{type(exc).__name__}: {exc}"
        raw_llm_json = {}

    llm_json = normalize_llm_answer(raw_llm_json, fallback_answer)

    result = {
        "mode": mode,
        "prompt": prompt,
        "raw_llm_answer": raw_llm_json,
        "llm_answer": llm_json,
    }

    if llm_error:
        result["llm_error"] = llm_error

    return result