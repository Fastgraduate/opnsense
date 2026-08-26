# train_final.csv로 모델 학습하고 inference_bundle.joblib 저장
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from scipy.sparse import hstack
from sklearn.linear_model import LogisticRegression

from src.utils.io import read_json, read_csv, ensure_dir, write_csv
from src.utils.seed import set_seed
from src.preprocess.normalize import build_preprocessed_frame, NormalizationConfig
from src.features.tfidf_vectorizer import fit_vectorizers, transform_vectorizers
from src.features.ngram_selector import extract_top_ngrams_per_class
from src.features.class_score_features import build_class_score_features
from src.features.handcrafted import build_handcrafted_features
from src.models.bundle import save_bundle
from src.evaluation.report import evaluate_predictions


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train TF-IDF only Logistic Regression model for web attack classification."
    )
    parser.add_argument("--processed-dir", default="data/processed")
    parser.add_argument("--labels-config", default="configs/labels.json")
    parser.add_argument("--train-config", default="configs/train.json")
    parser.add_argument("--artifact-dir", default="artifacts")
    parser.add_argument("--output-dir", default="outputs")
    return parser.parse_args()


def main():
    args = parse_args()

    labels_cfg = read_json(args.labels_config)
    train_cfg = read_json(args.train_config)

    target_classes = labels_cfg["target_classes"]
    attack_classes = [c for c in target_classes if c != "Normal"]

    set_seed(train_cfg.get("random_state", 42))

    processed = Path(args.processed_dir)
    train_df = read_csv(processed / "train_final_plus_http_params.csv")
    valid_df = read_csv(processed / "valid_final.csv")

    norm_cfg = NormalizationConfig(
        lowercase=True,
        decode_rounds=2,
        collapse_whitespace=True,
        keep_newlines=False,
        mask_digits=False,
        mask_hex_literals=False,
    )

    train_p = build_preprocessed_frame(train_df, config=norm_cfg)
    valid_p = build_preprocessed_frame(valid_df, config=norm_cfg)

    print("[run_train] fitting TF-IDF vectorizers...")
    char_vec, word_vec, X_char_train, X_word_train = fit_vectorizers(train_p["tfidf_text"], train_cfg)
    X_char_valid, X_word_valid = transform_vectorizers(char_vec, word_vec, valid_p["tfidf_text"])

    # 최종 학습 입력: TF-IDF only
    X_train = hstack([X_char_train, X_word_train])
    X_valid = hstack([X_char_valid, X_word_valid])

    print("[run_train] training Logistic Regression with TF-IDF only...")
    clf = LogisticRegression(
        max_iter=5000,
        solver="liblinear",
        class_weight="balanced",
        C=0.5,
        random_state=42,
    )
    clf.fit(X_train, train_p["label"])

    pred = clf.predict(X_valid)

    evaluate_predictions(
        valid_p["label"],
        pred,
        labels=target_classes,
        output_dir=args.output_dir,
        name="valid",
        extra_df=valid_p[["sample_id", "source_file", "payload", "label"]],
    )

    # 분석용 top ngram은 train 기준으로 계속 저장한다.
    # 단, 최종 모델 입력에는 dense feature를 붙이지 않는다.
    print("[run_train] extracting top n-grams for analysis only...")
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

    # 분석용 dense column 목록도 저장한다.
    # run_analysis.py에서 feature_distribution을 계속 사용할 수 있게 하기 위함이다.
    train_score = build_class_score_features(X_char_train, X_word_train, top_ngrams)
    train_hand = build_handcrafted_features(train_p["tfidf_text"])
    dense_columns = list(train_hand.join(train_score).columns)

    artifact_dir = Path(args.artifact_dir)
    ensure_dir(artifact_dir / "models")
    ensure_dir(artifact_dir / "vocab")

    vocab_rows = []
    for cls, data in top_ngrams.items():
        for rank, token in enumerate(data.get("char_ngrams", []), start=1):
            vocab_rows.append({"class": cls, "type": "char", "rank": rank, "ngram": token})
        for rank, token in enumerate(data.get("word_ngrams", []), start=1):
            vocab_rows.append({"class": cls, "type": "word", "rank": rank, "ngram": token})

    write_csv(pd.DataFrame(vocab_rows), artifact_dir / "vocab" / "top_ngrams.csv")

    bundle = {
        "version": "all_classes_v2_tfidf_only",
        "feature_mode": "tfidf_only",
        "target_classes": target_classes,
        "attack_classes": attack_classes,
        "model_type": "LogisticRegression_TFIDF_only",
        "model": clf,
        "char_vectorizer": char_vec,
        "word_vectorizer": word_vec,
        "top_ngrams": top_ngrams,
        "dense_columns": dense_columns,
        "dense_scaler": None,
        "normalization_config": {
            "lowercase": True,
            "decode_rounds": 2,
            "collapse_whitespace": True,
            "keep_newlines": False,
            "mask_digits": False,
            "mask_hex_literals": False,
        },
    }

    save_bundle(bundle, artifact_dir / "models" / "inference_bundle.joblib")

    print("[run_train] saved bundle:", artifact_dir / "models" / "inference_bundle.joblib")
    print("[run_train] feature_mode: tfidf_only")


if __name__ == "__main__":
    main()
