# 도구명을 [TOOL]로 마스킹한 뒤 성능이 얼마나 떨어지는지 비교한다. 성능이 크게 떨어지면 도구명 shortcut 의존 가능성이 높다.

from __future__ import annotations

from pathlib import Path
import re

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report

from src.models.bundle import load_bundle
from src.models.predict import predict_payloads
from src.utils.io import ensure_dir, read_csv, write_csv


DEFAULT_TOOL_PATTERNS = [
    r"sqlmap",
    r"nmap",
    r"masscan",
    r"nikto",
    r"acunetix",
    r"nessus",
    r"openvas",
    r"wpscan",
    r"dirbuster",
    r"gobuster",
    r"nuclei",
    r"hydra",
    r"burp",
    r"zap",
    r"arachni",
]


def mask_tool_names(payload: str, patterns: list[str] | None = None) -> str:
    patterns = patterns or DEFAULT_TOOL_PATTERNS
    out = str(payload)
    for pat in patterns:
        out = re.sub(pat, "[TOOL]", out, flags=re.I)
    return out


def run_toolname_mask_eval(
    dataset_path: str | Path,
    bundle_path: str | Path = "artifacts/models/inference_bundle.joblib",
    output_dir: str | Path = "outputs/analysis",
    name: str = "toolmask",
) -> pd.DataFrame:
    """도구명을 마스킹하기 전/후 성능 차이를 비교한다.

    성능이 크게 떨어지면 모델이 공격 행위보다 도구명 shortcut에 의존했을 가능성이 있다.
    """
    output_dir = ensure_dir(output_dir)
    df = read_csv(dataset_path)
    bundle = load_bundle(bundle_path)
    labels = bundle["target_classes"]

    original_pred = predict_payloads(df, bundle)

    masked_df = df.copy()
    masked_df["payload"] = masked_df["payload"].apply(mask_tool_names)
    masked_pred = predict_payloads(masked_df, bundle)

    rows = []
    for label_name, pred_df in [("original", original_pred), ("toolname_masked", masked_pred)]:
        y_true = pred_df["label"]
        y_pred = pred_df["prediction"]
        rows.append({
            "condition": label_name,
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        })

        report_df = pd.DataFrame(classification_report(
            y_true,
            y_pred,
            labels=labels,
            output_dict=True,
            zero_division=0,
        )).T.reset_index().rename(columns={"index": "label"})
        write_csv(report_df, Path(output_dir) / f"{name}_{label_name}_classification_report.csv")

    summary = pd.DataFrame(rows)
    # delta: masked - original
    if len(summary) == 2:
        delta = {
            "condition": "delta_masked_minus_original",
            "accuracy": summary.loc[1, "accuracy"] - summary.loc[0, "accuracy"],
            "macro_f1": summary.loc[1, "macro_f1"] - summary.loc[0, "macro_f1"],
            "weighted_f1": summary.loc[1, "weighted_f1"] - summary.loc[0, "weighted_f1"],
        }
        summary = pd.concat([summary, pd.DataFrame([delta])], ignore_index=True)

    write_csv(summary, Path(output_dir) / f"{name}_toolname_mask_eval.csv")

    compare = df.copy()
    compare["original_prediction"] = original_pred["prediction"]
    compare["masked_prediction"] = masked_pred["prediction"]
    compare["changed"] = compare["original_prediction"] != compare["masked_prediction"]
    changed = compare[compare["changed"]].copy()
    write_csv(changed, Path(output_dir) / f"{name}_prediction_changed_after_tool_mask.csv")

    masked_errors = masked_pred.copy()
    masked_errors = masked_errors[masked_errors["label"] != masked_errors["prediction"]]
    write_csv(masked_errors, Path(output_dir) / f"{name}_masked_misclassified_samples.csv")

    print(f"[toolname_mask_test] saved: {Path(output_dir) / f'{name}_toolname_mask_eval.csv'}")
    print(summary)
    return summary
