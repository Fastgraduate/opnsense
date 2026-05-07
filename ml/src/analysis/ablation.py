# char_only, word_only, tfidf_only, dense_handcrafted_only, dense_score_only, tfidf_plus_dense_all 실험을 재학습해서 피처 그룹별 기여도를 비교한다.

from __future__ import annotations

from pathlib import Path
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score

from src.utils.io import ensure_dir, read_csv, read_json, write_csv
from src.preprocess.normalize import build_preprocessed_frame, NormalizationConfig
from src.features.tfidf_vectorizer import fit_vectorizers, transform_vectorizers
from src.features.ngram_selector import extract_top_ngrams_per_class
from src.features.class_score_features import build_class_score_features
from src.features.handcrafted import build_handcrafted_features


def run_ablation(
    processed_dir: str | Path = "data/processed",
    labels_config: str | Path = "configs/labels.json",
    train_config: str | Path = "configs/train.json",
    output_dir: str | Path = "outputs/analysis",
) -> pd.DataFrame:
    """피처 그룹별 ablation 실험.

    실험 조건:
    - char_only
    - word_only
    - tfidf_only
    - dense_handcrafted_only
    - dense_score_only
    - dense_all_only
    - tfidf_plus_dense_all

    목적:
    어떤 피처 그룹이 실제 성능에 기여하는지 확인한다.
    """
    output_dir = ensure_dir(output_dir)
    labels_cfg = read_json(labels_config)
    train_cfg = read_json(train_config)

    target_classes = labels_cfg["target_classes"]
    attack_classes = [c for c in target_classes if c != "Normal"]

    processed_dir = Path(processed_dir)
    train_df = read_csv(processed_dir / "train_final.csv")
    valid_df = read_csv(processed_dir / "valid_final.csv")

    cfg = NormalizationConfig(lowercase=True, decode_rounds=2, collapse_whitespace=True)
    train_p = build_preprocessed_frame(train_df, config=cfg)
    valid_p = build_preprocessed_frame(valid_df, config=cfg)

    char_vec, word_vec, X_char_train, X_word_train = fit_vectorizers(train_p["tfidf_text"], train_cfg)
    X_char_valid, X_word_valid = transform_vectorizers(char_vec, word_vec, valid_p["tfidf_text"])

    top_k = train_cfg.get("top_k", {})
    top_ngrams = extract_top_ngrams_per_class(
        X_char_train,
        X_word_train,
        train_p["label"],
        classes=attack_classes,
        char_vec=char_vec,
        word_vec=word_vec,
        top_k_char=top_k.get("char", 300),
        top_k_word=top_k.get("word", 150),
    )

    train_score = build_class_score_features(X_char_train, X_word_train, top_ngrams)
    valid_score = build_class_score_features(X_char_valid, X_word_valid, top_ngrams)

    train_hand = build_handcrafted_features(train_p["tfidf_text"])
    valid_hand = build_handcrafted_features(valid_p["tfidf_text"])

    y_train = train_p["label"]
    y_valid = valid_p["label"]

    experiments = {}

    experiments["char_only"] = (X_char_train, X_char_valid)
    experiments["word_only"] = (X_word_train, X_word_valid)
    experiments["tfidf_only"] = (hstack([X_char_train, X_word_train]), hstack([X_char_valid, X_word_valid]))

    # dense 계열은 scaling 필요
    dense_groups = {
        "dense_handcrafted_only": (train_hand, valid_hand),
        "dense_score_only": (train_score, valid_score),
        "dense_all_only": (train_hand.join(train_score), valid_hand.join(valid_score)),
    }

    for name, (tr, va) in dense_groups.items():
        va = va.reindex(columns=tr.columns, fill_value=0.0)
        scaler = StandardScaler()
        tr_scaled = scaler.fit_transform(tr)
        va_scaled = scaler.transform(va)
        experiments[name] = (csr_matrix(tr_scaled), csr_matrix(va_scaled))

    dense_all_train = train_hand.join(train_score)
    dense_all_valid = valid_hand.join(valid_score).reindex(columns=dense_all_train.columns, fill_value=0.0)
    scaler = StandardScaler()
    dense_train_scaled = scaler.fit_transform(dense_all_train)
    dense_valid_scaled = scaler.transform(dense_all_valid)

    experiments["tfidf_plus_dense_all"] = (
        hstack([X_char_train, X_word_train, csr_matrix(dense_train_scaled)]),
        hstack([X_char_valid, X_word_valid, csr_matrix(dense_valid_scaled)]),
    )

    rows = []
    for name, (X_tr, X_va) in experiments.items():
        print(f"[ablation] training: {name}")
        clf = LogisticRegression(
            max_iter=4000,
            class_weight="balanced",
            solver="saga",
            n_jobs=-1,
        )
        clf.fit(X_tr, y_train)
        pred = clf.predict(X_va)

        rows.append({
            "experiment": name,
            "accuracy": float(accuracy_score(y_valid, pred)),
            "macro_f1": float(f1_score(y_valid, pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_valid, pred, average="weighted", zero_division=0)),
        })

    out = pd.DataFrame(rows).sort_values("macro_f1", ascending=False)
    write_csv(out, Path(output_dir) / "ablation_results.csv")
    print(f"[ablation] saved: {Path(output_dir) / 'ablation_results.csv'}")
    print(out)
    return out
