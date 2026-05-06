from __future__ import annotations

from pathlib import Path
import hashlib

import pandas as pd

from src.data.loader import load_web_payload_dataset
from src.preprocess.normalize import normalize_text, NormalizationConfig
from src.utils.io import ensure_dir, write_csv


def payload_hash(payload: str) -> str:
    norm = normalize_text(payload, NormalizationConfig(lowercase=True, decode_rounds=2, collapse_whitespace=True))
    return hashlib.md5(norm.encode("utf-8", errors="ignore")).hexdigest()


def clean_dataset(
    source: str,
    interim_dir: str,
    target_classes: list[str],
    label_aliases: dict[str, str] | None = None,
    remove_cross_split_duplicates: bool = True,
) -> dict[str, pd.DataFrame]:
    interim = ensure_dir(interim_dir)

    df = load_web_payload_dataset(source, aliases=label_aliases)
    before = len(df)

    df = df[df["label"].isin(target_classes)].copy()
    df = df[df["payload"].fillna("").astype(str).str.strip() != ""].copy()

    df["payload_hash"] = df["payload"].apply(payload_hash)

    # 동일 payload+label 중복 제거
    df = df.drop_duplicates(subset=["payload_hash", "label"]).copy()

    # 동일 payload에 서로 다른 라벨이 붙은 경우 격리
    label_counts = df.groupby("payload_hash")["label"].nunique()
    conflict_hashes = set(label_counts[label_counts > 1].index)
    conflicts = df[df["payload_hash"].isin(conflict_hashes)].copy()
    df = df[~df["payload_hash"].isin(conflict_hashes)].copy()

    train = df[df["source_split"] == "train"].copy()
    test = df[df["source_split"] == "test"].copy()
    unspecified = df[df["source_split"] == "unspecified"].copy()

    # 공식 split이 없거나 한쪽이 비어있으면 split 생성은 build_splits에서 처리한다.
    if len(train) == 0 and len(test) == 0:
        train = unspecified.copy()
        test = pd.DataFrame(columns=df.columns)
    else:
        train = pd.concat([train, unspecified], ignore_index=True)

    # train/test 간 동일 payload hash 제거: test를 기준으로 train 중복 제거
    cross_split_removed = pd.DataFrame(columns=df.columns)
    if remove_cross_split_duplicates and len(train) and len(test):
        test_hashes = set(test["payload_hash"])
        cross_split_removed = train[train["payload_hash"].isin(test_hashes)].copy()
        train = train[~train["payload_hash"].isin(test_hashes)].copy()

    write_csv(train, interim / "train_clean.csv")
    write_csv(test, interim / "test_clean.csv")
    write_csv(conflicts, interim / "quarantine_label_conflicts.csv")
    write_csv(cross_split_removed, interim / "quarantine_cross_split_duplicates.csv")

    summary = pd.DataFrame([
        {"item": "raw_rows", "count": before},
        {"item": "clean_train_rows", "count": len(train)},
        {"item": "clean_test_rows", "count": len(test)},
        {"item": "label_conflicts", "count": len(conflicts)},
        {"item": "cross_split_duplicates_removed", "count": len(cross_split_removed)},
    ])
    write_csv(summary, interim / "cleaning_summary.csv")

    print("[clean_dataset] label distribution - train")
    print(train["label"].value_counts())
    if len(test):
        print("[clean_dataset] label distribution - test")
        print(test["label"].value_counts())

    return {
        "train_clean": train,
        "test_clean": test,
        "conflicts": conflicts,
        "cross_split_removed": cross_split_removed,
    }
