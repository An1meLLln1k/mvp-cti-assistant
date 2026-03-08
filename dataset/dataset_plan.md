# Dataset Plan

## 1. Purpose
Цель создания корпуса CVE — поддержка retrieval, RAG и evaluation интеллектуального ассистента для анализа киберугроз. 
На текущем этапе корпус используется прежде всего как retrieval-база и источник контекста для будущего RAG-прототипа, а также как основа для последующих экспериментов по классификации и оценке.

## 2. Data Sources
- National Vulnerability Database (NVD), year feeds JSON 2.0 за 2024–2026 годы
- CISA Known Exploited Vulnerabilities (KEV), CSV-каталог
- MITRE CWE List (XML) — для построения иерархии CWE

## 3. Selection Criteria
Текущая версия корпуса включает:
- все CVE из NVD year feeds за 2024–2026 годы;
- обогащение записей KEV-метаданными по совпадению `cve_id`;
- дополнительное обогащение иерархическими полями CWE.

Примечание:
на текущем этапе KEV используется как источник признака реальной эксплуатируемости и сопутствующих метаданных, а не как отдельный независимый корпус записей.D

### 4.1 Основные поля CVE
- `cve_id` (string) — идентификатор CVE
- `description` (string | null) — текстовое описание уязвимости
- `published_date` (string | null) — дата/время публикации CVE в формате ISO
- `last_modified_date` (string | null) — дата/время последнего обновления записи
- `cwe` (array[string]) — список CWE, если указан в NVD
- `references` (array[string]) — ссылки на связанные источники
- `source` (string) — основной источник записи (`"NVD"`)
- `kev` (bool) — присутствует ли CVE в CISA KEV

### 4.2 Поля CVSS / risk metadata
- `cvss` (object | null) — агрегированные CVSS-данные, если доступны
- `kev_vendor_project` (string | null)
- `kev_product` (string | null)
- `kev_date_added` (string | null)
- `kev_due_date` (string | null)
- `kev_required_action` (string | null)
- `kev_notes` (string | null)
- `kev_ransomware_use` (string | null)

### 4.3 Пример записи (JSONL)
{
  "cve_id": "...",
  "description": "...",
  "published_date": "YYYY-MM-DD",
  "severity": null,
  "cwe": ["CWE-XXX"],
  "cwe_primary_id": "CWE-XXX",
  "cwe_parent_id": null,
  "cwe_top_id": null,
  "cwe_depth": null,
  "cwe_path": null,
  "references": ["..."],
  "source": "KEV"
}
```json
{"cve_id":"CVE-2026-21519",
"description":"...",
"published_date":"2026-02-10",
"severity":null,
"cwe":["CWE-843"],
"cwe_primary_id":"CWE-843",
"cwe_parent_id":null,
"cwe_top_id":null,
"cwe_depth":null,
"cwe_path":null,
"references":["https://nvd.nist.gov/vuln/detail/CVE-2026-21519"],
"source":"KEV"}

Поля CWE-иерархии добавлены для поддержки иерархической классификации (coarse-to-fine): сначала верхнеуровневая категория, затем уточнение до конкретного CWE.

## 5. Format
JSON Lines (JSONL), одна запись — один CVE.

## 6. Limitations
- Возможны неполные описания
- CVSS не всегда отражает реальную эксплуатируемость
- Смещение в сторону публично раскрытых уязвимостей
