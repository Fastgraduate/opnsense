# Logistic Regression의 클래스별 상위 positive/negative 계수를 뽑음. 모델이 어떤 n-gram/피처를 보고 특정 클래스로 판단하는지 확인한다.
from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

from src.models.bundle import load_bundle
from src.utils.io import ensure_dir, write_csv


def _feature_names_from_bundle(bundle: dict) -> list[str]:
    char_vec = bundle["char_vectorizer"]
    word_vec = bundle["word_vectorizer"]

    char_names = [f"char::{x}" for x in char_vec.get_feature_names_out()]
    word_names = [f"word::{x}" for x in word_vec.get_feature_names_out()]
    dense_names = [f"dense::{x}" for x in bundle["dense_columns"]]

    return char_names + word_names + dense_names


def analyze_coefficients(
    bundle_path: str | Path = "artifacts/models/inference_bundle.joblib",
    output_dir: str | Path = "outputs/analysis",
    name: str = "valid",
    top_k: int = 50,
) -> pd.DataFrame:
    """Logistic Regression의 클래스별 상위 양/음 계수를 추출한다.

    양의 계수:
        해당 클래스로 예측하게 만드는 방향의 피처
    음의 계수:
        해당 클래스로 예측하지 않게 만드는 방향의 피처
    """
    output_dir = ensure_dir(output_dir)
    bundle = load_bundle(bundle_path)
    model = bundle["model"]

    if not hasattr(model, "coef_"):
        raise TypeError("bundle['model'] does not expose coef_. This analysis expects LogisticRegression-like model.")

    feature_names = np.array(_feature_names_from_bundle(bundle))
    coef = model.coef_

    # sklearn multiclass logistic: coef shape = [n_classes, n_features]
    # binary일 경우도 classes_ 기준으로 처리
    classes = list(model.classes_)

    rows = []
    for class_idx, cls in enumerate(classes):
        coefs = coef[class_idx]

        pos_idx = np.argsort(coefs)[-top_k:][::-1]
        neg_idx = np.argsort(coefs)[:top_k]

        for rank, idx in enumerate(pos_idx, start=1):
            rows.append({
                "class": cls,
                "direction": "positive",
                "rank": rank,
                "feature": feature_names[idx],
                "coefficient": float(coefs[idx]),
                "bias_flag": _flag_feature(feature_names[idx]),
            })

        for rank, idx in enumerate(neg_idx, start=1):
            rows.append({
                "class": cls,
                "direction": "negative",
                "rank": rank,
                "feature": feature_names[idx],
                "coefficient": float(coefs[idx]),
                "bias_flag": _flag_feature(feature_names[idx]),
            })

    out = pd.DataFrame(rows)
    write_csv(out, Path(output_dir) / f"{name}_top_coef_by_class.csv")
    print(f"[coefficient_analysis] saved: {Path(output_dir) / f'{name}_top_coef_by_class.csv'}")
    return out


def _flag_feature(feature_name: str) -> str:
    f = feature_name.lower()
    tool_names = [
        "sqlmap", "nmap", "masscan", "nikto", "acunetix", "nessus",
        "openvas", "wpscan", "dirbuster", "gobuster", "nuclei", "hydra",
    ]
    for tool in tool_names:
        if tool in f:
            return "tool_name_bias"

    generic = ["user-agent", "host:", "accept:", "connection:"]
    for token in generic:
        if token in f:
            return "header_format_bias"

    if "payload_length" in f:
        return "length_bias_candidate"

    return ""
