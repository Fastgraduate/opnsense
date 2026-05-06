from __future__ import annotations

from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

from src.utils.io import ensure_dir, read_csv, write_csv


def sample_by_ratio(
    df: pd.DataFrame,
    ratio: dict[str, float],
    total_size: int | None = None,
    random_state: int = 42,
) -> pd.DataFrame:
    parts = []
    available = {label: len(df[df["label"] == label]) for label in ratio}

    if total_size is None:
        # 각 클래스 목표 비율을 만족할 수 있는 최대 크기 산정
        candidates = []
        for label, r in ratio.items():
            if r <= 0:
                continue
            candidates.append(int(available.get(label, 0) / r))
        total_size = min(candidates) if candidates else len(df)

    for label, r in ratio.items():
        sub = df[df["label"] == label]
        n = min(len(sub), int(round(total_size * r)))
        if n > 0:
            parts.append(sub.sample(n=n, random_state=random_state))

    if not parts:
        return pd.DataFrame(columns=df.columns)

    out = pd.concat(parts, ignore_index=True)
    return out.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def split_train_valid(
    train_clean: pd.DataFrame,
    valid_size: float,
    random_state: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    counts = train_clean["label"].value_counts()
    # stratify는 각 클래스가 2개 이상 있어야 안전하다.
    stratify = train_clean["label"] if (counts.min() >= 2 and len(counts) > 1) else None
    train_final, valid_final = train_test_split(
        train_clean,
        test_size=valid_size,
        random_state=random_state,
        stratify=stratify,
    )
    return train_final.reset_index(drop=True), valid_final.reset_index(drop=True)


def build_splits(
    interim_dir: str,
    processed_dir: str,
    target_classes: list[str],
    train_ratio: dict[str, float],
    test_balanced_ratio: dict[str, float],
    test_realistic_ratio: dict[str, float],
    valid_size: float = 0.2,
    random_state: int = 42,
    test_size_if_no_official_split: float = 0.2,
) -> dict[str, pd.DataFrame]:
    interim = Path(interim_dir)
    processed = ensure_dir(processed_dir)

    train_clean = read_csv(interim / "train_clean.csv")
    test_clean_path = interim / "test_clean.csv"
    test_clean = read_csv(test_clean_path) if test_clean_path.exists() else pd.DataFrame(columns=train_clean.columns)

    # 공식 test가 없으면 train_clean에서 test_clean 생성
    if len(test_clean) == 0:
        counts = train_clean["label"].value_counts()
        stratify = train_clean["label"] if (counts.min() >= 2 and len(counts) > 1) else None
        train_clean, test_clean = train_test_split(
            train_clean,
            test_size=test_size_if_no_official_split,
            random_state=random_state,
            stratify=stratify,
        )
        train_clean = train_clean.reset_index(drop=True)
        test_clean = test_clean.reset_index(drop=True)
        write_csv(train_clean, interim / "train_clean.csv")
        write_csv(test_clean, interim / "test_clean.csv")

    # 학습은 class-balanced 목표 비율에 맞춰 downsample
    train_balanced = sample_by_ratio(train_clean, train_ratio, random_state=random_state)
    if len(train_balanced) == 0:
        raise ValueError("train_balanced is empty. Check label distribution and target ratios.")

    train_final, valid_final = split_train_valid(train_balanced, valid_size, random_state)

    test_balanced = sample_by_ratio(test_clean, test_balanced_ratio, random_state=random_state)
    test_realistic = sample_by_ratio(test_clean, test_realistic_ratio, random_state=random_state)

    write_csv(train_final, processed / "train_final.csv")
    write_csv(valid_final, processed / "valid_final.csv")
    write_csv(test_balanced, processed / "test_balanced.csv")
    write_csv(test_realistic, processed / "test_realistic.csv")

    dist_rows = []
    for name, frame in [
        ("train_final", train_final),
        ("valid_final", valid_final),
        ("test_balanced", test_balanced),
        ("test_realistic", test_realistic),
    ]:
        vc = frame["label"].value_counts()
        for label in target_classes:
            dist_rows.append({"dataset": name, "label": label, "count": int(vc.get(label, 0))})
    write_csv(pd.DataFrame(dist_rows), processed / "dataset_distribution.csv")

    print("[build_splits] saved datasets to", processed)
    print(pd.DataFrame(dist_rows).pivot(index="label", columns="dataset", values="count").fillna(0).astype(int))

    return {
        "train_final": train_final,
        "valid_final": valid_final,
        "test_balanced": test_balanced,
        "test_realistic": test_realistic,
    }
