from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

from src.utils.io import ensure_dir, write_csv


def evaluate_predictions(y_true, y_pred, labels: list[str], output_dir: str | Path, name: str, extra_df: pd.DataFrame | None = None) -> dict:
    output_dir = Path(output_dir)
    reports_dir = ensure_dir(output_dir / "reports")
    confusion_dir = ensure_dir(output_dir / "confusion")
    error_dir = ensure_dir(output_dir / "error_analysis")

    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    report_df = pd.DataFrame(report).T
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    cm_df = pd.DataFrame(cm, index=[f"true_{x}" for x in labels], columns=[f"pred_{x}" for x in labels])

    write_csv(report_df.reset_index().rename(columns={"index": "label"}), reports_dir / f"{name}_classification_report.csv")
    write_csv(cm_df.reset_index().rename(columns={"index": "true_label"}), confusion_dir / f"{name}_confusion_matrix.csv")

    if extra_df is not None:
        err = extra_df.copy()
        err["y_true"] = list(y_true)
        err["y_pred"] = list(y_pred)
        err = err[err["y_true"] != err["y_pred"]]
        write_csv(err, error_dir / f"{name}_misclassified_samples.csv")

    summary = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }

    print(f"===== {name} =====")
    for k, v in summary.items():
        print(f"{k}: {v:.4f}")
    print(classification_report(y_true, y_pred, labels=labels, digits=4, zero_division=0))
    print(cm_df)

    return summary
