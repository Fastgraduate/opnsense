from __future__ import annotations

from pathlib import Path
from typing import Iterator
import zipfile
import io

import pandas as pd

from src.preprocess.label_map import normalize_label


CSV_ENCODINGS = ("utf-8-sig", "utf-8", "cp949", "latin1")


def _read_csv_bytes(raw: bytes) -> pd.DataFrame:
    last_err = None
    for enc in CSV_ENCODINGS:
        try:
            return pd.read_csv(io.BytesIO(raw), encoding=enc)
        except Exception as exc:
            last_err = exc
    raise ValueError(f"CSV decode failed: {last_err}")


def _iter_csv_frames(source: str | Path) -> Iterator[tuple[str, pd.DataFrame]]:
    path = Path(source)

    if path.is_file() and path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".csv"):
                    continue
                yield name, _read_csv_bytes(zf.read(name))
        return

    if path.is_dir():
        for file in sorted(path.rglob("*.csv")):
            yield str(file.relative_to(path)), _read_csv_bytes(file.read_bytes())
        return

    if path.is_file() and path.suffix.lower() == ".csv":
        yield path.name, _read_csv_bytes(path.read_bytes())
        return

    raise FileNotFoundError(f"Unsupported source: {source}")


def infer_split(source_name: str) -> str:
    lower = source_name.lower()
    if "train" in lower or "training" in lower:
        return "train"
    if "test" in lower or "testing" in lower:
        return "test"
    return "unspecified"


def infer_label_from_filename(source_name: str) -> str | None:
    # 파일/폴더명에 클래스명이 들어있는 데이터셋 대응용
    name = source_name.replace("\\", "/")
    candidates = [
        "Cross_Site_Scripting",
        "HOST_Scan",
        "Path_Disclosure",
        "SQL_Injection",
        "System_Cmd_Execution",
        "Vulnerability_Scan",
        "Normal",
        "Training_Normals",
    ]
    for c in candidates:
        if c.lower() in name.lower():
            return normalize_label(c)
    return None


def standardize_frame(df: pd.DataFrame, source_name: str, aliases: dict[str, str] | None = None) -> pd.DataFrame:
    lower_cols = {str(c).lower(): c for c in df.columns}
    payload_col = lower_cols.get("payload")
    label_col = lower_cols.get("label_action") or lower_cols.get("label")
    id_col = lower_cols.get("log_number") or lower_cols.get("id")

    if payload_col is None:
        raise ValueError(f"payload column not found in {source_name}: {list(df.columns)}")

    out = pd.DataFrame()
    out["payload"] = df[payload_col].fillna("").astype(str)

    if label_col is not None:
        out["raw_label"] = df[label_col].astype(str).str.strip()
    else:
        inferred = infer_label_from_filename(source_name)
        if inferred is None:
            raise ValueError(f"label column not found and label cannot be inferred from filename: {source_name}")
        out["raw_label"] = inferred

    out["label"] = out["raw_label"].apply(lambda x: normalize_label(x, aliases=aliases))
    out["source_file"] = source_name
    out["source_split"] = infer_split(source_name)

    if id_col is not None:
        out["source_row_id"] = df[id_col].astype(str)
    else:
        out["source_row_id"] = [str(i) for i in range(len(df))]

    out["sample_id"] = out["source_file"].astype(str) + "::" + out["source_row_id"].astype(str)
    return out[["sample_id", "source_file", "source_split", "source_row_id", "payload", "raw_label", "label"]]


def load_web_payload_dataset(
    source: str | Path,
    aliases: dict[str, str] | None = None,
) -> pd.DataFrame:
    frames = []
    errors = []
    for name, frame in _iter_csv_frames(source):
        try:
            frames.append(standardize_frame(frame, name, aliases=aliases))
        except Exception as exc:
            errors.append({"source_file": name, "error": str(exc)})

    if not frames:
        msg = "No usable CSV files loaded."
        if errors:
            msg += f" Errors: {errors[:5]}"
        raise ValueError(msg)

    df = pd.concat(frames, ignore_index=True)
    if errors:
        print("[WARN] Some CSV files were skipped:")
        for err in errors[:10]:
            print(" -", err)
    return df
