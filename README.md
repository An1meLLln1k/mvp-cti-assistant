# Progress report

## Что уже реализовано

### 1. Базовая структура MVP-проекта
Собрана рабочая структура репозитория:
- `app/` — код ассистента и retrieval
- `tools/` — утилиты для сборки и обработки данных
- `dataset/` — корпуса данных и артефакты
- `runs/` — логи запусков и eval-отчёты

---

### 2. Иерархия CWE
Реализован парсинг локальной копии официального CWE XML (`cwec_v4.19.1.xml`) и построена иерархия CWE.

Получен файл:
- `dataset/cwe_hierarchy.json`

В иерархии для CWE используются поля:
- `parent_id`
- `top_id`
- `depth`
- `path`
- `is_leaf`

Эта структура нужна для последующей coarse-to-fine постановки задач по CWE.

---

### 3. Малый прототип корпуса
На раннем этапе был собран небольшой prototype/sample-корпус:
- `dataset/dataset_v1.jsonl`

Он использовался для:
- отладки retrieval
- отладки CLI-прототипа
- проверки логирования
- первичной evaluation retrieval baseline

То есть `dataset_v1.jsonl` — это не основной корпус, а ранняя тестовая версия.

---

### 4. Сборка реального корпуса CVE из NVD + KEV
Реализован ingestion-пайплайн сборки корпуса CVE из внешних источников:

#### Источники:
1. **NVD JSON 2.0 year feeds**
   - `nvdcve-2.0-2024.json`
   - `nvdcve-2.0-2025.json`
   - `nvdcve-2.0-2026.json`

2. **CISA Known Exploited Vulnerabilities (KEV)**
   - `known_exploited_vulnerabilities.csv`

#### Что делает пайплайн:
- читает CVE-данные из NVD
- нормализует записи в единый JSONL-формат
- объединяет их с данными CISA KEV
- добавляет KEV-метаданные для известных эксплуатируемых CVE

#### Результат:
Получен файл:
- `dataset/dataset_v2.jsonl`

Это уже не sample, а основной корпус CVE для прототипа.

#### Объём корпуса:
- NVD 2024: **39 007** записей
- NVD 2025: **43 423** записей
- NVD 2026: **6 161** записей

Итоговый размер:
- **88 591 CVE-запись**

Также было загружено:
- **1 536 KEV-записей**

---

### 5. Обогащение корпуса иерархией CWE
На следующем этапе корпус `dataset_v2.jsonl` был обогащён иерархическими полями CWE с использованием `cwe_hierarchy.json`.

Получен файл:
- `dataset/dataset_v2_enriched.jsonl`

Добавляемые поля:
- `cwe_primary_id`
- `cwe_parent_id`
- `cwe_top_id`
- `cwe_depth`
- `cwe_path`
- `cwe_is_leaf`

#### Результаты обогащения:
- Всего записей: **88 591**
- Обогащено иерархией CWE: **81 290**
- Без CWE: **7 101**
- CWE не найдены в локальной иерархии: **200**

На текущем этапе именно `dataset_v2_enriched.jsonl` является основной рабочей версией корпуса для retrieval и будущего RAG-прототипа.

---

### 6. Retrieval baseline
Реализован retrieval baseline в CLI-прототипе:
- запрос пользователя
- поиск по локальному корпусу
- возврат структурированного ответа
- логирование результата в `runs/`

Команда запуска:
```powershell
py -3 -m app.cli "CVE-2026-2441"
## Rebuild full corpus on another machine

```powershell
New-Item -ItemType Directory -Force -Path .\dataset\raw\nvd | Out-Null
New-Item -ItemType Directory -Force -Path .\dataset\raw\kev | Out-Null

Invoke-WebRequest "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip" -OutFile ".\dataset\raw\nvd\nvdcve-2.0-2024.json.zip"
Invoke-WebRequest "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.zip" -OutFile ".\dataset\raw\nvd\nvdcve-2.0-2025.json.zip"
Invoke-WebRequest "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip" -OutFile ".\dataset\raw\nvd\nvdcve-2.0-2026.json.zip"

Expand-Archive ".\dataset\raw\nvd\nvdcve-2.0-2024.json.zip" -DestinationPath ".\dataset\raw\nvd" -Force
Expand-Archive ".\dataset\raw\nvd\nvdcve-2.0-2025.json.zip" -DestinationPath ".\dataset\raw\nvd" -Force
Expand-Archive ".\dataset\raw\nvd\nvdcve-2.0-2026.json.zip" -DestinationPath ".\dataset\raw\nvd" -Force

Invoke-WebRequest "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv" -OutFile ".\dataset\raw\kev\known_exploited_vulnerabilities.csv"

py -3 tools\build_dataset_v2.py
py -3 tools\enrich_dataset_with_cwe.py