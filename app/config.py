from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
RUNS_DIR = ROOT / "runs"

DATASET_PATH = DATASET_DIR / "dataset_v2_enriched.jsonl"
TOP_K = 5