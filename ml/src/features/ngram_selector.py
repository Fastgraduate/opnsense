from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.feature_selection import chi2


def top_indices_chi2(X, y_binary, k: int) -> np.ndarray:
    scores, _ = chi2(X, y_binary)
    scores = np.nan_to_num(scores, nan=0.0, posinf=0.0, neginf=0.0)
    k = min(k, X.shape[1])
    if k <= 0:
        return np.array([], dtype=int)
    return np.argsort(scores)[-k:][::-1]


def extract_top_ngrams_per_class(
    X_char,
    X_word,
    y,
    classes: list[str],
    char_vec,
    word_vec,
    top_k_char: int = 300,
    top_k_word: int = 150,
) -> dict:
    out = {}
    y_arr = pd.Series(y).astype(str)

    char_vocab = np.array(char_vec.get_feature_names_out())
    word_vocab = np.array(word_vec.get_feature_names_out())

    for cls in classes:
        if cls == "Normal":
            continue

        y_bin = (y_arr == cls).astype(int)
        char_idx = top_indices_chi2(X_char, y_bin, top_k_char)
        word_idx = top_indices_chi2(X_word, y_bin, top_k_word)

        out[cls] = {
            "char_indices": char_idx.tolist(),
            "word_indices": word_idx.tolist(),
            "char_ngrams": char_vocab[char_idx].tolist(),
            "word_ngrams": word_vocab[word_idx].tolist(),
        }
    return out
