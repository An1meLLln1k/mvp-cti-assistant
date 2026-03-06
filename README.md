# mvp-cti-assistant

MVP интеллектуального ассистента для анализа киберугроз (CVE) на базе RAG-подхода.

## Что есть
- Локальный корпус CVE в JSONL (`dataset/dataset_v1.jsonl`)
- CWE-иерархия (`dataset/cwe_hierarchy.json`)
- CLI ассистента: retrieval → структурированный ответ → логирование
- Eval retrieval: Recall@K, MRR

## Запуск
```powershell
py -3 -m app.cli "CVE-2026-2441"
py -3 tools\eval_retrieval.py
