# 원본 CSV/ZIP을 읽어서 정제하고 train/valid/test로 나눔

from __future__ import annotations

import argparse
from pathlib import Path

from src.data.clean_dataset import clean_dataset
from src.data.build_splits import build_splits
from src.utils.io import read_json


def parse_args():
    parser = argparse.ArgumentParser(
        description="Prepare cleaned train/valid/test datasets for web attack classification."
    )

    parser.add_argument(
        "--source",
        required=True,
        help="Raw dataset path. Can be ZIP file, CSV file, or directory containing CSV files.",
    )

    parser.add_argument(
        "--labels-config",
        default="configs/labels.json",
        help="Path to label config JSON.",
    )

    parser.add_argument(
        "--train-config",
        default="configs/train.json",
        help="Path to training/split config JSON.",
    )

    parser.add_argument(
        "--interim-dir",
        default="data/interim",
        help="Directory to save cleaned intermediate datasets.",
    )

    parser.add_argument(
        "--processed-dir",
        default="data/processed",
        help="Directory to save final train/valid/test datasets.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    labels_cfg = read_json(args.labels_config)
    train_cfg = read_json(args.train_config)

    target_classes = labels_cfg["target_classes"]
    label_aliases = labels_cfg.get("label_aliases", {})

    Path(args.interim_dir).mkdir(parents=True, exist_ok=True)
    Path(args.processed_dir).mkdir(parents=True, exist_ok=True)

    print("[1/2] Cleaning raw dataset...")

    clean_dataset(
        source=args.source,
        interim_dir=args.interim_dir,
        target_classes=target_classes,
        label_aliases=label_aliases,
    )

    print("[2/2] Building train/valid/test splits...")

    build_splits(
        interim_dir=args.interim_dir,
        processed_dir=args.processed_dir,
        target_classes=target_classes,
        train_ratio=train_cfg["train_ratio"],
        test_balanced_ratio=train_cfg["test_balanced_ratio"],
        test_realistic_ratio=train_cfg["test_realistic_ratio"],
        valid_size=train_cfg.get("valid_size", 0.2),
        random_state=train_cfg.get("random_state", 42),
        test_size_if_no_official_split=train_cfg.get("test_size_if_no_official_split", 0.2),
    )

    print("[DONE] Dataset preparation completed.")
    print(f"- Cleaned files: {args.interim_dir}")
    print(f"- Final datasets: {args.processed_dir}")


if __name__ == "__main__":
    main()