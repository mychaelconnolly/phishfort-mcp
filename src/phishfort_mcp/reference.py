from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_DIR = PROJECT_ROOT / "docs" / "reference"


def read_reference_file(name: str) -> str:
    path = REFERENCE_DIR / name
    return path.read_text(encoding="utf-8")
