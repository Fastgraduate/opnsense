from __future__ import annotations

import numpy as np
import pandas as pd


PREFIX_MAP = {
    "Cross_Site_Scripting": "xss",
    "HOST_Scan": "hostscan",
    "Path_Disclosure": "pathdisclosure",
    "SQL_Injection": "sqli",
    "System_Cmd_Execution": "cmdexec",
    "Vulnerability_Scan": "vulnscan",
}


def _score_block(X, indices: list[int], prefix: str) -> pd.DataFrame:
    if not indices:
        n = X.shape[0]
        return pd.DataFrame({
            f"{prefix}_score": np.zeros(n),
            f"{prefix}_hit_count": np.zeros(n),
            f"{prefix}_max_score": np.zeros(n),
        })

    sub = X[:, indices]
    score = np.asarray(sub.sum(axis=1)).ravel()
    hit_count = np.asarray((sub > 0).sum(axis=1)).ravel()
    max_score = sub.max(axis=1).toarray().ravel()

    return pd.DataFrame({
        f"{prefix}_score": score,
        f"{prefix}_hit_count": hit_count,
        f"{prefix}_max_score": max_score,
    })


def build_class_score_features(X_char, X_word, top_ngrams: dict) -> pd.DataFrame:
    parts = []
    total_cols = []

    for cls, data in top_ngrams.items():
        prefix = PREFIX_MAP.get(cls, cls.lower())
        char_block = _score_block(X_char, data.get("char_indices", []), f"{prefix}_char")
        word_block = _score_block(X_word, data.get("word_indices", []), f"{prefix}_word")
        total = char_block[f"{prefix}_char_score"] + word_block[f"{prefix}_word_score"]

        block = pd.concat([char_block, word_block], axis=1)
        block[f"{prefix}_total_score"] = total
        parts.append(block)
        total_cols.append(f"{prefix}_total_score")

    if parts:
        out = pd.concat(parts, axis=1)
    else:
        out = pd.DataFrame(index=range(X_char.shape[0]))

    if total_cols:
        totals = out[total_cols].values
        sorted_scores = np.sort(totals, axis=1)
        out["top_class_score"] = sorted_scores[:, -1]
        out["second_class_score"] = sorted_scores[:, -2] if len(total_cols) >= 2 else 0.0
        out["score_margin"] = out["top_class_score"] - out["second_class_score"]

        # 주요 혼동 가능 클래스 간 경계 피처
        if "hostscan_total_score" in out.columns and "vulnscan_total_score" in out.columns:
            out["hostscan_minus_vulnscan"] = out["hostscan_total_score"] - out["vulnscan_total_score"]
        if "cmdexec_total_score" in out.columns and "pathdisclosure_total_score" in out.columns:
            out["cmdexec_minus_path"] = out["cmdexec_total_score"] - out["pathdisclosure_total_score"]
        if "sqli_total_score" in out.columns and "xss_total_score" in out.columns:
            out["sqli_minus_xss"] = out["sqli_total_score"] - out["xss_total_score"]

    return out.fillna(0.0)
