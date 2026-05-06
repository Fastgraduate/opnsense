from __future__ import annotations

from scipy.sparse import hstack, csr_matrix

from src.preprocess.normalize import build_preprocessed_frame, NormalizationConfig
from src.features.tfidf_vectorizer import transform_vectorizers
from src.features.handcrafted import build_handcrafted_features
from src.features.class_score_features import build_class_score_features


def transform_for_bundle(df, bundle):
    """bundle 설정에 맞춰 추론 입력 행렬을 생성한다.

    지원 mode:
    - tfidf_only
        X = [char TF-IDF] + [word TF-IDF]
    - tfidf_plus_dense_all 또는 legacy
        X = [char TF-IDF] + [word TF-IDF] + [scaled dense]

    반환:
    - X: 모델 입력 행렬
    - dfp: 전처리된 DataFrame
    - dense: 분석용 dense feature DataFrame
    """
    cfg = NormalizationConfig(**bundle.get("normalization_config", {}))
    dfp = build_preprocessed_frame(df, payload_col="payload", config=cfg)

    X_char, X_word = transform_vectorizers(
        bundle["char_vectorizer"],
        bundle["word_vectorizer"],
        dfp["tfidf_text"],
    )

    feature_mode = bundle.get("feature_mode", "tfidf_plus_dense_all")

    # 분석용 dense feature는 계속 계산한다.
    # 최종 모델이 tfidf_only여도 feature_distribution 분석에서 필요하다.
    top_ngrams = bundle.get("top_ngrams", {})
    if top_ngrams:
        score_df = build_class_score_features(X_char, X_word, top_ngrams)
    else:
        score_df = None

    handcrafted_df = build_handcrafted_features(dfp["tfidf_text"])

    if score_df is not None:
        dense = handcrafted_df.join(score_df)
    else:
        dense = handcrafted_df

    dense_columns = bundle.get("dense_columns")
    if dense_columns:
        dense = dense.reindex(columns=dense_columns, fill_value=0.0)

    if feature_mode == "tfidf_only":
        X = hstack([X_char, X_word])
        return X, dfp, dense

    # legacy: dense를 모델 입력에 붙이는 예전 방식
    dense_scaler = bundle.get("dense_scaler")
    if dense_scaler is None:
        X = hstack([X_char, X_word])
        return X, dfp, dense

    dense_scaled = dense_scaler.transform(dense)
    X = hstack([X_char, X_word, csr_matrix(dense_scaled)])
    return X, dfp, dense


def predict_payloads(df, bundle):
    X, dfp, dense = transform_for_bundle(df, bundle)
    model = bundle["model"]
    pred = model.predict(X)

    result = dfp.copy()
    result["prediction"] = pred

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        for i, cls in enumerate(model.classes_):
            result[f"proba_{cls}"] = proba[:, i]

    return result
