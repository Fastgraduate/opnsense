from __future__ import annotations

from pathlib import Path
import joblib

from src.utils.io import ensure_dir


def save_bundle(bundle: dict, path: str | Path) -> None:
    path = Path(path)
    ensure_dir(path.parent)
    joblib.dump(bundle, path)


def load_bundle(path: str | Path) -> dict:
    return joblib.load(path)
