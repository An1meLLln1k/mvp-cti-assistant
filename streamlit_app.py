import re
from datetime import datetime

import pandas as pd
import streamlit as st

from app.config import DATASET_PATH, TOP_K
from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve
from app.rag.answer import build_answer
from app.rag.generate import generate_rag_answer


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


st.set_page_config(
    page_title="Интеллектуальный ассистент для анализа киберугроз",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def load_records():
    return load_jsonl(DATASET_PATH)


def format_published_date(value: str, with_time: bool = False) -> str:
    if not value:
        return "—"

    text = str(value).strip()

    try:
        dt = datetime.fromisoformat(text)
        return dt.strftime("%d.%m.%Y %H:%M") if with_time else dt.strftime("%d.%m.%Y")
    except Exception:
        return text


def build_retrieval_table(hits):
    rows = []
    for idx, (score, rec) in enumerate(hits, start=1):
        rows.append(
            {
                "Место": idx,
                "Релевантность": round(float(score), 3),
                "CVE-ID": rec.get("cve_id"),
                "KEV": "Да" if rec.get("kev") else "Нет",
                "Осн. CWE": rec.get("cwe_primary_id"),
                "Верх. CWE": rec.get("cwe_top_id"),
                "Дата": format_published_date(rec.get("published_date")),
            }
        )
    return pd.DataFrame(rows)


def detect_query_type(query: str) -> str:
    return "CVE-ID" if CVE_RE.search(query or "") else "Текстовый"


def detect_context_status(hits) -> str:
    return "Найден" if hits else "Не найден"


def detect_mode_label(use_llm: bool, hits) -> str:
    if not hits:
        return "No-hit"
    if use_llm:
        return "LLM + корпус"
    return "Без LLM"


def extract_display_fields(final_answer, fallback_answer, hits):
    """
    Приводит результат к единому виду для отображения
    и в режиме с LLM, и в retrieval-only режиме.
    """
    if not hits:
        return {
            "summary": "По запросу не найден релевантный контекст в локальном корпусе.",
            "actions": [],
            "kev": "Нет",
            "grounded": "Нет",
            "cwe_primary": "—",
            "cwe_top": "—",
            "notes": (
                "Надёжное совпадение в корпусе не найдено. "
                "Результат не следует трактовать как подтверждённую информацию "
                "по конкретной уязвимости."
            ),
        }

    # Режим с LLM
    if isinstance(final_answer, dict) and "items" not in final_answer:
        cwe = final_answer.get("cwe") or {}
        return {
            "summary": final_answer.get("summary") or "—",
            "actions": final_answer.get("actions") or [],
            "kev": "Да" if final_answer.get("kev") else "Нет",
            "grounded": "Да" if final_answer.get("grounded") else "Нет",
            "cwe_primary": cwe.get("primary") or "—",
            "cwe_top": cwe.get("top") or "—",
            "notes": final_answer.get("notes") or "",
        }

    # Retrieval-only fallback
    items = fallback_answer.get("items") or []
    top = items[0] if items else {}
    cwe = top.get("cwe") or {}

    return {
        "summary": fallback_answer.get("summary") or "—",
        "actions": fallback_answer.get("actions") or [],
        "kev": "Да" if top.get("kev") else "Нет",
        "grounded": "Да" if hits else "Нет",
        "cwe_primary": cwe.get("primary") or "—",
        "cwe_top": cwe.get("top") or "—",
        "notes": "Результат сформирован без интерпретации языковой моделью.",
    }


def prettify_notes(notes: str, hits, query_type: str) -> str:
    text = (notes or "").strip()

    if not hits:
        return (
            "Надёжное совпадение в корпусе не найдено. "
            "Результат не следует трактовать как подтверждённую информацию "
            "по конкретной уязвимости."
        )

    lowered = text.lower()

    if not text:
        return (
            "Ответ предназначен для первичной оценки и должен дополнительно "
            "проверяться по исходным источникам."
        )

    if query_type == "CVE-ID" and "недостаточно" in lowered:
        return (
            "Ответ предназначен для первичной оценки и должен дополнительно "
            "проверяться по исходным источникам."
        )

    if "локальной модели" in lowered or "нормализац" in lowered:
        return (
            "Ответ предназначен для первичной оценки и должен дополнительно "
            "проверяться по исходным источникам."
        )

    return text


def render_actions(actions):
    if not actions:
        st.write("Для данного сценария отдельные действия не сформированы.")
        return

    for idx, action in enumerate(actions, start=1):
        st.write(f"{idx}. {action}")


def render_top_hit_card(hits):
    if not hits:
        st.warning("Поиск по корпусу не вернул релевантных результатов.")
        return

    score, rec = hits[0]
    refs = rec.get("references") or []

    st.markdown("#### Наиболее релевантная запись")
    st.write(f"**Идентификатор уязвимости (CVE-ID):** {rec.get('cve_id') or '—'}")
    st.write(f"**Релевантность:** {round(float(score), 3)}")
    st.write(f"**Подтверждённая эксплуатация (KEV):** {'Да' if rec.get('kev') else 'Нет'}")
    st.write(f"**Основной тип слабости (CWE):** {rec.get('cwe_primary_id') or '—'}")
    st.write(f"**Верхнеуровневый класс слабости (CWE):** {rec.get('cwe_top_id') or '—'}")
    st.write(f"**Дата публикации:** {format_published_date(rec.get('published_date'), with_time=True)}")
    st.write(f"**Описание:** {rec.get('description') or '—'}")

    if refs:
        st.write(f"**Первая ссылка:** {refs[0]}")


def main():
    st.title("Интеллектуальный ассистент для анализа киберугроз")

    st.markdown(
        """
Демонстрационный интерфейс показывает базовый сценарий первичного анализа уязвимости:
- ввод запроса в виде **CVE-ID** или **текстового описания**;
- поиск релевантного контекста в локальном корпусе;
- формирование структурированного результата;
- корректную обработку сценария **no-hit**, когда надёжный контекст не найден.
"""
    )

    llm_mode = "ollama"

    with st.sidebar:
        st.subheader("Параметры запуска")

        query = st.text_area(
            "Запрос пользователя",
            value="что за CVE-2026-1731 и что делать",
            height=100,
        )

        top_k = st.slider(
            "Количество документов для контекста (Top-K)",
            min_value=1,
            max_value=10,
            value=int(TOP_K),
        )

        use_llm = st.checkbox("Использовать языковую модель (LLM)", value=True)

        if use_llm:
            llm_mode = st.selectbox(
                "Режим языковой модели",
                ["ollama", "mock"],
                index=0,
            )

        with st.expander("Дополнительные параметры"):
            show_prompt = st.checkbox(
                "Показать инструкцию для модели",
                value=False,
            )
            show_fallback = st.checkbox(
                "Показать базовый ответ без языковой модели",
                value=False,
            )
            show_raw_llm = st.checkbox(
                "Показать сырой ответ модели до нормализации",
                value=False,
            )

        run_clicked = st.button("Запустить анализ", type="primary", use_container_width=True)

    if not run_clicked:
        st.info("Введи запрос слева и нажми «Запустить анализ».")
        return

    if not query.strip():
        st.warning("Запрос пустой.")
        return

    try:
        records = load_records()
    except Exception as exc:
        st.error(f"Не удалось загрузить корпус: {type(exc).__name__}: {exc}")
        return

    try:
        with st.spinner("Выполняется анализ..."):
            hits = retrieve(query, records, top_k=top_k)
            fallback_answer = build_answer(query, hits)

            rag_result = None
            final_answer = fallback_answer

            if use_llm:
                rag_result = generate_rag_answer(
                    query=query,
                    hits=hits,
                    fallback_answer=fallback_answer,
                    mode=llm_mode,
                )
                final_answer = rag_result["llm_answer"]

    except Exception as exc:
        st.error(f"Ошибка во время обработки запроса: {type(exc).__name__}: {exc}")
        return

    query_type = detect_query_type(query)
    context_status = detect_context_status(hits)
    mode_label = detect_mode_label(use_llm, hits)
    display = extract_display_fields(final_answer, fallback_answer, hits)

    st.subheader("Статус запроса")
    s1, s2, s3 = st.columns(3)

    with s1:
        st.metric("Тип запроса", query_type)
        st.caption("CVE-ID — идентификатор уязвимости; текстовый — описание проблемы")

    with s2:
        st.metric("Надёжный контекст", context_status)
        st.caption("Показывает, найдено ли достаточное совпадение в локальном корпусе")

    with s3:
        st.metric("Способ формирования ответа", mode_label)
        st.caption("LLM + корпус — ответ с языковой моделью и опорой на найденные данные")

    col_left, col_right = st.columns([1.25, 0.75])

    with col_left:
        st.subheader("Результат анализа")

        with st.container(border=True):
            st.markdown("#### Краткая сводка")
            st.write(display["summary"])

        c1, c2, c3 = st.columns(3)
        c1.metric("Подтверждённая эксплуатация (KEV)", display["kev"])
        c2.metric("Опора на найденный контекст", display["grounded"])
        c3.metric("Надёжный контекст", context_status)

        with st.container(border=True):
            st.markdown("#### Классификация слабости")
            st.write(f"**Основной тип слабости (CWE):** {display['cwe_primary']}")
            st.write(f"**Верхнеуровневый класс слабости (CWE):** {display['cwe_top']}")

        with st.container(border=True):
            st.markdown("#### Рекомендуемые действия")
            render_actions(display["actions"])

        with st.container(border=True):
            st.markdown("#### Ограничения интерпретации")
            st.write(prettify_notes(display["notes"], hits, query_type))

        with st.expander("Техническое представление ответа (JSON)"):
            st.json(final_answer)

        if show_fallback:
            with st.expander("Базовый ответ без языковой модели"):
                st.json(fallback_answer)

        if use_llm and rag_result is not None and show_raw_llm:
            with st.expander("Сырой ответ модели до нормализации"):
                st.json(rag_result.get("raw_llm_answer", {}))

        if use_llm and rag_result is not None and show_prompt:
            with st.expander("Инструкция для модели"):
                st.code(rag_result.get("prompt", ""), language="text")

    with col_right:
        st.subheader("Найденные источники")

        with st.container(border=True):
            if hits:
                df = build_retrieval_table(hits)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.warning("Надёжное совпадение в корпусе не найдено.")

        with st.container(border=True):
            render_top_hit_card(hits)

        with st.expander("Сырые результаты поиска (для отладки)"):
            if not hits:
                st.write("Пусто.")
            else:
                for i, (score, rec) in enumerate(hits, start=1):
                    st.markdown(f"**Совпадение {i}**")
                    st.write(
                        {
                            "score": round(float(score), 3),
                            "cve_id": rec.get("cve_id"),
                            "kev": rec.get("kev"),
                            "cwe_primary_id": rec.get("cwe_primary_id"),
                            "cwe_top_id": rec.get("cwe_top_id"),
                            "published_date": format_published_date(rec.get("published_date"), with_time=True),
                            "description": rec.get("description"),
                            "references": rec.get("references") or [],
                        }
                    )


if __name__ == "__main__":
    main()