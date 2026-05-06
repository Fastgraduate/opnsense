# 클래스별 피처 평균, 중앙값, 0 비율, bias ratio를 계산한다. 특정 피처가 어느 클래스에 과하게 쏠리는지 분석

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

from src.models.bundle import load_bundle
from src.models.predict import transform_for_bundle
from src.utils.io import ensure_dir, read_csv, write_csv


def _safe_second_largest(values: np.ndarray) -> float:
    values = np.asarray(values, dtype=float)
    if len(values) == 0:
        return 0.0
    sorted_values = np.sort(values)[::-1]
    if len(sorted_values) == 1:
        return 0.0
    return float(sorted_values[1])


def analyze_feature_distribution(
    dataset_path: str | Path,
    bundle_path: str | Path = "artifacts/models/inference_bundle.joblib",
    output_dir: str | Path = "outputs/analysis",
    name: str = "valid",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """클래스별 dense 피처 분포와 피처 편향 점수를 계산한다.

    분석 대상:
    - handcrafted feature
    - class score feature
    - margin feature

    TF-IDF 전체 차원은 너무 크므로 여기서는 dense 피처만 분석한다.
    ngram 자체는 ngram_audit.py와 coefficient_analysis.py에서 별도로 본다.
    """
    output_dir = ensure_dir(output_dir)

    df = read_csv(dataset_path)
    bundle = load_bundle(bundle_path)

    _, dfp, dense = transform_for_bundle(df, bundle)
    dense = dense.copy()
    dense["label"] = dfp["label"].values

    rows = []
    feature_cols = [c for c in dense.columns if c != "label"]

    for feature in feature_cols:
        for label, sub in dense.groupby("label"):
            s = sub[feature].astype(float)
            rows.append({
                "feature": feature,
                "label": label,
                "count": int(len(s)),
                "mean": float(s.mean()),
                "median": float(s.median()),
                "std": float(s.std(ddof=0)),
                "min": float(s.min()),
                "max": float(s.max()),
                "zero_ratio": float((s == 0).mean()),
            })

    dist_df = pd.DataFrame(rows)

    bias_rows = []
    for feature, group in dist_df.groupby("feature"):
        g = group.sort_values("mean", ascending=False).reset_index(drop=True)
        top_mean = float(g.loc[0, "mean"]) if len(g) else 0.0
        top_label = str(g.loc[0, "label"]) if len(g) else ""
        second_mean = _safe_second_largest(g["mean"].values)

        eps = 1e-12
        if second_mean <= eps:
            bias_ratio = np.inf if top_mean > eps else 0.0
        else:
            bias_ratio = top_mean / second_mean

        nonzero_labels = int((group["mean"].astype(float) > eps).sum())

        if np.isinf(bias_ratio) or bias_ratio >= 10:
            bias_level = "very_high"
        elif bias_ratio >= 5:
            bias_level = "high"
        elif bias_ratio >= 2:
            bias_level = "medium"
        else:
            bias_level = "low"

        bias_rows.append({
            "feature": feature,
            "top_label": top_label,
            "top_mean": top_mean,
            "second_mean": second_mean,
            "bias_ratio": float(bias_ratio) if not np.isinf(bias_ratio) else "inf",
            "nonzero_label_count": nonzero_labels,
            "bias_level": bias_level,
            "interpretation_hint": _interpret_feature_bias(feature, top_label, bias_level),
        })

    bias_df = pd.DataFrame(bias_rows).sort_values(
        by=["bias_level", "feature"],
        ascending=[True, True],
    )

    write_csv(dist_df, Path(output_dir) / f"{name}_feature_distribution_by_class.csv")
    write_csv(bias_df, Path(output_dir) / f"{name}_feature_bias_score.csv")

    print(f"[feature_distribution] saved:")
    print(f" - {Path(output_dir) / f'{name}_feature_distribution_by_class.csv'}")
    print(f" - {Path(output_dir) / f'{name}_feature_bias_score.csv'}")

    return dist_df, bias_df


def _interpret_feature_bias(feature: str, top_label: str, bias_level: str) -> str:
    """피처 편향 해석 힌트. 최종 판정은 사람이 top ngram/오분류와 함께 봐야 한다."""
    if bias_level in {"low", "medium"}:
        return "분포 확인 필요"

    f = feature.lower()
    if "tool" in f or "scanner" in f:
        return "도구명 편향 가능성 높음"
    if "length" in f:
        return "길이 shortcut 가능성 점검"
    if "score" in f and top_label != "Normal":
        return "공격별 score 편향. top ngram 품질 확인"
    if "scan" in f and top_label in {"HOST_Scan", "Vulnerability_Scan"}:
        return "스캔 계열 경계 혼동 가능성 점검"
    if "path" in f and top_label in {"Path_Disclosure", "System_Cmd_Execution"}:
        return "Path/CmdExec 경계 혼동 가능성 점검"
    return "강한 클래스 쏠림. 공격 본질인지 데이터 shortcut인지 확인"
