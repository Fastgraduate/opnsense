# char TF-IDF, word TF-IDF, dense feature 등 피처별 성능 비교
from __future__ import annotations

import argparse

from src.analysis.ablation import run_ablation


def parse_args():
    p = argparse.ArgumentParser(description="Run ablation experiments.")
    p.add_argument("--processed-dir", default="data/processed")
    p.add_argument("--labels-config", default="configs/labels.json")
    p.add_argument("--train-config", default="configs/train.json")
    p.add_argument("--output-dir", default="outputs/analysis")
    return p.parse_args()


def main():
    args = parse_args()
    run_ablation(
        processed_dir=args.processed_dir,
        labels_config=args.labels_config,
        train_config=args.train_config,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
