from __future__ import annotations

import argparse

from src.utils.io import read_csv
from src.models.bundle import load_bundle
from src.models.predict import predict_payloads
from src.evaluation.report import evaluate_predictions


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", default="artifacts/models/inference_bundle.joblib")
    p.add_argument("--test", required=True)
    p.add_argument("--name", default="test")
    p.add_argument("--output-dir", default="outputs")
    return p.parse_args()


def main():
    args = parse_args()
    bundle = load_bundle(args.bundle)
    df = read_csv(args.test)

    result = predict_payloads(df, bundle)
    evaluate_predictions(
        result["label"],
        result["prediction"],
        labels=bundle["target_classes"],
        output_dir=args.output_dir,
        name=args.name,
        extra_df=result[["sample_id", "source_file", "payload", "label", "prediction"]],
    )


if __name__ == "__main__":
    main()
