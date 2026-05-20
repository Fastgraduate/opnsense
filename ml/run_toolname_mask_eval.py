# sqlmap, nmap, nikto 같은 도구명 의존성 검사
from __future__ import annotations

import argparse

from src.analysis.toolname_mask_test import run_toolname_mask_eval


def parse_args():
    p = argparse.ArgumentParser(description="Evaluate tool-name bias by masking scanner/tool names.")
    p.add_argument("--dataset", default="data/processed/test_balanced.csv")
    p.add_argument("--bundle", default="artifacts/models/inference_bundle.joblib")
    p.add_argument("--output-dir", default="outputs/analysis")
    p.add_argument("--name", default="toolmask")
    return p.parse_args()


def main():
    args = parse_args()
    run_toolname_mask_eval(
        dataset_path=args.dataset,
        bundle_path=args.bundle,
        output_dir=args.output_dir,
        name=args.name,
    )


if __name__ == "__main__":
    main()
