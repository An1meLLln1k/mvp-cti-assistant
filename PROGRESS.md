# Progress report 07.08.26

## Что уже реализовано

1. Собран MVP-репозиторий проекта с основной структурой:
   - `app/`
   - `dataset/`
   - `tools/`
   - `runs/`

2. Подготовлен прототип локального корпуса CVE в формате JSONL:
   - `dataset_v1.jsonl`

3. Реализован парсинг официального CWE XML (`cwec_v4.19.1.xml`) и построена иерархия CWE
:
   - `cwe_parent_id`
   - `cwe_top_id`
   - `cwe_depth`
   - `cwe_path`
   - `cwe_is_leaf`

4. Датасет обогащён иерархическими полями CWE для последующей постановки coarse-to-fine классификации.

5. Реализован CLI-прототип ассистента:
   - запрос пользователя
   - retrieval по локальному корпусу
   - структурированный ответ
   - логирование результата в `runs/`

6. Реализован baseline retrieval evaluation:
   - benchmark в JSONL
   - метрики `Recall@K`
   - метрика `MRR`

7. Расширен benchmark:
   - точечные запросы по CVE-ID
   - перефразированные запросы
   - описательные запросы
   - negative cases для проверки `no_hits`

8. Реализована отдельная метрика `no_hit_accuracy` для негативных кейсов.


## Текущий статус

На текущем этапе получен воспроизводимый MVP retrieval-контура:
`query -> retrieval -> structured answer -> logging -> eval`
## Промежуточные результаты retrieval baseline

На sample-бенчмарке получены следующие результаты:
- Recall@3 = 1.000
- MRR = 1.000
- No-hit accuracy = 0.833

Вывод:
baseline retrieval на текущем прототипе корпуса стабильно находит релевантные CVE-записи и в большинстве негативных кейсов корректно возвращает отсутствие релевантного результата.

Проект успешно воспроизводится на другой машине после клонирования из GitHub.

## Следующие шаги

1. Собрать более крупный корпус данных из NVD + CISA KEV.
2. Построить `dataset_v2` / `dataset_full` для работы уже не на sample-наборе, а на реальном объёме.
3. Усилить retrieval (exact match + смысловой retrieval).
4. Подключить LLM и реализовать RAG v0.
5. Разделить evaluation на retrieval и generation.
6. Добавить использование CWE-иерархии в coarse-to-fine постановке.
## Корпус данных проекта

В проекте используются несколько уровней данных:
### 08.03.2026
### 1. `cwe_hierarchy.json`
Локально построенная иерархия CWE на основе локальной копии официального CWE XML (`cwec_v4.19.1.xml`).
Файл содержит служебное отображение CWE -> parent/top/depth/path/is_leaf и используется для coarse-to-fine постановки задач по CWE.

### 2. `dataset_v1.jsonl`
Небольшой sample / prototype dataset.
Использовался на раннем этапе для быстрой проверки пайплайна retrieval, логирования и evaluation.

### 3. `dataset_v2.jsonl`
Нормализованный корпус CVE, собранный из официальных NVD JSON 2.0 year feeds (2024, 2025, 2026) и дополнительно обогащённый данными CISA KEV.
Каждая строка JSONL соответствует одной CVE-записи.

### 4. `dataset_v2_enriched.jsonl`
Расширенная версия `dataset_v2.jsonl`, дополнительно обогащённая иерархическими полями CWE:
- `cwe_primary_id`
- `cwe_parent_id`
- `cwe_top_id`
- `cwe_depth`
- `cwe_path`
- `cwe_is_leaf`

Этот файл является основной рабочей версией корпуса для retrieval и последующего RAG-прототипа.
## Что сделано на текущем этапе

1. Реализован ingestion-пайплайн для сборки корпуса CVE из NVD JSON 2.0 year feeds.
2. Реализовано подключение CISA KEV и обогащение записей признаком known exploited vulnerability.
3. Собран единый JSONL-корпус `dataset_v2.jsonl`.
4. Реализовано обогащение корпуса иерархией CWE и получен `dataset_v2_enriched.jsonl`.
5. Ранее собранный retrieval baseline и evaluation-пайплайн подготовлены к переключению с sample-dataset на реальный корпус.

---

- `dataset_v1.jsonl` — **маленький тестовый корпус**, ранняя версия для отладки.
- `dataset_v2.jsonl` — **большой нормализованный корпус CVE**, собранный из **NVD + KEV**.
- `dataset_v2_enriched.jsonl` — **тот же большой корпус**, но уже **с иерархией CWE**.

То есть цепочка такая:

**NVD + KEV → dataset_v2.jsonl → + CWE hierarchy → dataset_v2_enriched.jsonl**


На реальном корпусе:
- почти **88.6k записей**,
- много похожих уязвимостей,
- поиск становится реально сложнее.

Поэтому:
- `Recall@3 = 0.810`
- `MRR = 0.778`

Это **не провал**, а честный baseline на реальном корпусе.

---

## Что делать дальше

**улучшаем retrieval на `dataset_v2_enriched.jsonl`, а потом уже подключать RAG v0.**

То есть порядок такой:

1. baseline retrieval на real corpus  
2. улучшение retrieval  
3. RAG v0  
4. evaluation generation  
5. потом уже думать про модели глубже

### 11.03.2026

Проведено улучшение retrieval baseline на реальном корпусе `dataset_v2_enriched.jsonl`.

Текущие результаты retrieval evaluation:
- `n_cases = 27`
- `positive_cases = 21`
- `negative_cases = 6`
- `Recall@3 = 0.952`
- `MRR = 0.905`
- `No-hit accuracy = 0.667`

Вывод:
retrieval baseline на реальном корпусе удалось заметно улучшить по сравнению с предыдущей версией.
На текущем этапе baseline считается достаточным для перехода к следующему шагу — подготовке RAG v0.

### 12.03.2026

Реализован RAG v0 контур в mock-режиме.

Что сделано:
- retrieval возвращает top-k релевантный контекст;
- реализована упаковка retrieval-контекста в структурированный prompt;
- реализован `llm_adapter` через `MockLLMClient`;
- реализован режим `--use-llm --llm-mode mock`;
- прототип возвращает структурированный grounded JSON-ответ:
  - `summary`
  - `actions`
  - `kev`
  - `cwe`
  - `references`
  - `grounded`
  - `notes`

Итог:
на текущем этапе получен полный RAG v0 pipeline без вызова внешней модели:

`query -> retrieval -> context -> llm_adapter -> structured answer -> logging`

Следующий шаг:
подключение реальной LLM вместо mock-клиента и сравнение качества retrieval-only vs RAG-output.

```powershell
git add PROGRESS.md
git commit -m "Update progress report with full corpus and retrieval results"
git push origin main