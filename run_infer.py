from __future__ import annotations

import argparse
import pandas as pd

from src.models.bundle import load_bundle
from src.models.predict import predict_payloads


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", default="artifacts/models/inference_bundle.joblib")
    p.add_argument("--payload", required=True)
    return p.parse_args()


def main():
    args = parse_args()
    bundle = load_bundle(args.bundle)

    df = pd.DataFrame([{
        "sample_id": "manual::0",
        "source_file": "manual",
        "source_split": "manual",
        "source_row_id": "0",
        "payload": args.payload,
        "raw_label": "",
        "label": "",
    }])

    result = predict_payloads(df, bundle)
    row = result.iloc[0]
    print("prediction:", row["prediction"])
    prob_cols = [c for c in result.columns if c.startswith("proba_")]
    for c in prob_cols:
        print(f"{c}: {row[c]:.4f}")


if __name__ == "__main__":
    main()
