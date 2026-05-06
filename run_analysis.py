from __future__ import annotations

import argparse

from src.analysis.feature_distribution import analyze_feature_distribution
from src.analysis.coefficient_analysis import analyze_coefficients
from src.analysis.ngram_audit import audit_top_ngrams


def parse_args():
    p = argparse.ArgumentParser(description="Run feature bias and coefficient analysis.")
    p.add_argument("--dataset", default="data/processed/valid_final.csv")
    p.add_argument("--bundle", default="artifacts/models/inference_bundle.joblib")
    p.add_argument("--output-dir", default="outputs/analysis")
    p.add_argument("--name", default="valid")
    p.add_argument("--top-k", type=int, default=50)
    return p.parse_args()


def main():
    args = parse_args()

    analyze_feature_distribution(
        dataset_path=args.dataset,
        bundle_path=args.bundle,
        output_dir=args.output_dir,
        name=args.name,
    )

    analyze_coefficients(
        bundle_path=args.bundle,
        output_dir=args.output_dir,
        name=args.name,
        top_k=args.top_k,
    )

    audit_top_ngrams(
        bundle_path=args.bundle,
        output_dir=args.output_dir,
        name=args.name,
    )

    print("[DONE] analysis completed.")


if __name__ == "__main__":
    main()
