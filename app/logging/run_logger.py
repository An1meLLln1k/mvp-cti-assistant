import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def log_run(runs_dir: Path, payload: Dict[str, Any]) -> Path:
    ensure_dir(runs_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = runs_dir / f"run_{ts}.jsonl"
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return out