from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer

from src.preprocess.tokenizer import web_payload_tokenizer


def make_char_vectorizer(
    ngram_range: tuple[int, int] = (3, 5),
    min_df: int = 3,
    max_features: int = 50000,
) -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="char",
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
        lowercase=False,
    )


def make_word_vectorizer(
    ngram_range: tuple[int, int] = (1, 2),
    min_df: int = 2,
    max_features: int = 25000,
) -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="word",
        tokenizer=web_payload_tokenizer,
        token_pattern=None,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
        lowercase=False,
    )


def fit_vectorizers(texts, config: dict):
    tfidf_cfg = config.get("tfidf", {})
    char_range = tuple(tfidf_cfg.get("char_ngram_range", [3, 5]))
    word_range = tuple(tfidf_cfg.get("word_ngram_range", [1, 2]))

    char_vec = make_char_vectorizer(
        ngram_range=char_range,
        min_df=tfidf_cfg.get("char_min_df", 3),
        max_features=tfidf_cfg.get("char_max_features", 50000),
    )
    word_vec = make_word_vectorizer(
        ngram_range=word_range,
        min_df=tfidf_cfg.get("word_min_df", 2),
        max_features=tfidf_cfg.get("word_max_features", 25000),
    )

    X_char = char_vec.fit_transform(texts)
    X_word = word_vec.fit_transform(texts)
    return char_vec, word_vec, X_char, X_word


def transform_vectorizers(char_vec, word_vec, texts):
    return char_vec.transform(texts), word_vec.transform(texts)
