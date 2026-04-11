import pandas as pd
import streamlit as st

from app.config import DATASET_PATH, TOP_K
from app.io.dataset_loader import load_jsonl
from app.retrieval.simple_retriever import retrieve
from app.rag.answer import build_answer
from app.rag.generate import generate_rag_answer


st.set_page_config(
    page_title="Интеллектуальный ассистент для анализа киберугроз",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def load_records():
    return load_jsonl(DATASET_PATH)


def build_retrieval_table(hits):
    rows = []
    for idx, (score, rec) in enumerate(hits, start=1):
        refs = rec.get("references") or []
        rows.append(
            {
                "Место в выдаче": idx,
                "Оценка релевантности": round(float(score), 3),
                "CVE (идентификатор уязвимости)": rec.get("cve_id"),
                "KEV (есть в каталоге эксплуатации)": "Да" if rec.get("kev") else "Нет",
                "CWE primary (основной тип слабости)": rec.get("cwe_primary_id"),
                "CWE top (верхнеуровневый класс)": rec.get("cwe_top_id"),
                "Дата публикации": rec.get("published_date"),
                "Описание": (rec.get("description") or "")[:200],
                "Первая ссылка": refs[0] if refs else "",
            }
        )
    return pd.DataFrame(rows)


def main():
    st.title("Архитектура интеллектуального ассистента для анализа киберугроз")

    with st.sidebar:
        st.subheader("Настройки")

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

        llm_mode = st.selectbox(
            "Режим генерации ответа (LLM mode)",
            ["ollama", "mock"],
            index=0,
        )

        show_prompt = st.checkbox(
            "Показать инструкцию для модели (prompt)",
            value=False,
        )

        show_fallback = st.checkbox(
            "Показать базовый ответ без LLM (fallback_answer)",
            value=False,
        )

        show_raw_llm = st.checkbox(
            "Показать сырой ответ модели до нормализации (raw_llm_answer)",
            value=False,
        )

        run_clicked = st.button("Запустить анализ", type="primary", use_container_width=True)

    st.markdown(
        """
**Что показывает демонстрация:**
- поиск по локальному корпусу данных (retrieval);
- базовый ответ без генерации модели (fallback baseline);
- ответ с использованием локальной языковой модели или тестового режима (local-RAG / mock-RAG);
- корректную обработку сценария отсутствия релевантных данных (no-hit).
"""
    )

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

    col1, col2 = st.columns([1.2, 0.8])

    with col1:
        st.subheader("Итоговый ответ системы")
        st.json(final_answer)

        if show_fallback:
            st.subheader("Базовый ответ без LLM (fallback_answer)")
            st.json(fallback_answer)

        if use_llm and rag_result is not None and show_raw_llm:
            st.subheader("Сырой ответ модели до нормализации (raw_llm_answer)")
            st.json(rag_result.get("raw_llm_answer", {}))

        if use_llm and rag_result is not None and show_prompt:
            st.subheader("Инструкция для модели (prompt)")
            st.code(rag_result.get("prompt", ""), language="text")

    with col2:
        st.subheader("Результаты поиска по корпусу (retrieval preview)")

        if hits:
            df = build_retrieval_table(hits)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.warning("Поиск по корпусу не вернул релевантных результатов.")

        st.subheader("Ключевые признаки результата")

        if not hits:
            st.write("Сценарий: **отсутствие релевантных данных (no-hit)**")
        elif use_llm:
            st.write(f"Сценарий: **RAG с режимом {llm_mode}**")
        else:
            st.write("Сценарий: **только поиск и базовый ответ (retrieval-only baseline)**")

        if isinstance(final_answer, dict):
            grounded = final_answer.get("grounded")
            kev = final_answer.get("kev")
            cwe = final_answer.get("cwe") or {}

            grounded_text = "Да" if grounded else "Нет"
            kev_text = "Да" if kev else "Нет"

            st.write(f"- grounded (ответ действительно опирается на найденный контекст): **{grounded_text}**")
            st.write(f"- KEV (уязвимость входит в каталог реально эксплуатируемых): **{kev_text}**")
            st.write(f"- CWE primary (основной тип слабости): **{cwe.get('primary')}**")
            st.write(f"- CWE top (верхнеуровневый класс слабости): **{cwe.get('top')}**")

        with st.expander("Подробные найденные записи (сырые retrieval hit'ы)"):
            for i, (score, rec) in enumerate(hits, start=1):
                st.markdown(f"**HIT {i}**")
                st.write(
                    {
                        "score": round(float(score), 3),
                        "cve_id": rec.get("cve_id"),
                        "kev": rec.get("kev"),
                        "cwe_primary_id": rec.get("cwe_primary_id"),
                        "cwe_top_id": rec.get("cwe_top_id"),
                        "published_date": rec.get("published_date"),
                        "description": rec.get("description"),
                        "references": rec.get("references") or [],
                    }
                )


if __name__ == "__main__":
    main()