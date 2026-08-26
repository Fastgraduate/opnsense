# retrain_bundle.py — 루트에서 실행: python retrain_bundle.py
from __future__ import annotations
import shutil
from pathlib import Path

from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from src.utils.io import read_csv
from src.preprocess.normalize import build_preprocessed_frame, NormalizationConfig
from src.features.tfidf_vectorizer import make_word_vectorizer
from src.models.bundle import save_bundle

# ---- 설정 ----
OUT      = Path("artifacts/models/inference_bundle.joblib")
TRAIN    = ["data/processed/train_final.csv", "data/processed/valid_final.csv"]
CLASSES  = ["Normal", "Cross_Site_Scripting", "HOST_Scan", "Path_Disclosure",
            "SQL_Injection", "System_Cmd_Execution", "Vulnerability_Scan"]
NORM_CFG = dict(lowercase=True, decode_rounds=2, collapse_whitespace=True,
                keep_newlines=False, mask_digits=False, mask_hex_literals=False)

def main():
    cfg = NormalizationConfig(**NORM_CFG)

    # 1) 학습 데이터 로드 + 추론과 동일한 tfidf_text 생성
    frames = []
    for p in TRAIN:
        df = read_csv(p)[["payload", "label"]]
        frames.append(build_preprocessed_frame(df, config=cfg))
    import pandas as pd
    train = pd.concat(frames, ignore_index=True)

    # 2) 벡터라이저 (char_wb 3-6 + word 1-2), tfidf_text 위에서 fit
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 6),
                            min_df=2, max_features=50000,
                            lowercase=False, sublinear_tf=True)
    word_vec = make_word_vectorizer(ngram_range=(1, 2), min_df=2, max_features=25000)
    Xc = char_vec.fit_transform(train["tfidf_text"])
    Xw = word_vec.fit_transform(train["tfidf_text"])
    X = hstack([Xc, Xw]).tocsr()

    # 3) 모델 (multinomial softmax, balanced, C=6)
    model = LogisticRegression(solver="lbfgs", C=6.0,
                            class_weight="balanced", max_iter=5000)
    model.fit(X, train["label"])

    # 4) shipped와 동일 포맷의 번들 구성
    bundle = {
        "model": model,
        "char_vectorizer": char_vec,
        "word_vectorizer": word_vec,
        "target_classes": CLASSES,
        "normalization_config": NORM_CFG,
        "feature_mode": "tfidf_only",
        "dense_columns": None,
        "dense_scaler": None,
        "top_ngrams": {},
        "model_note": "retrained char_wb(3,6)+word(1,2) LogReg C=6 balanced; train_final+valid_final",
    }

    # 5) 백업 후 덮어쓰기
    if OUT.exists():
        shutil.copy2(OUT, OUT.with_suffix(".backup.joblib"))
        print(f"백업: {OUT.with_suffix('.backup.joblib')}")
    save_bundle(bundle, OUT)
    print(f"저장 완료: {OUT}  (train rows={len(train)}, features={X.shape[1]})")

if __name__ == "__main__":
    main()