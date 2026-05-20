from pathlib import Path
import argparse
import html
import re
import urllib.parse

import pandas as pd

from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

ML_DIR = SCRIPT_DIR
DEFAULT_BASE = Path("ml/data/processed/train_final.csv")
DEFAULT_OUT = Path("ml/data/processed/train_final_plus_external.csv")

DEFAULT_EXTRA_FILES = [
    Path("ml/data/external/http_params_train_only_for_augmentation.csv"),
    Path("ml/data/external/honeypot_payload.csv"),
]


REQUIRED_COLUMNS = {"payload", "label_action"}


def deep_decode(text: str, rounds: int = 4) -> str:
    text = str(text)

    for _ in range(rounds):
        before = text
        text = urllib.parse.unquote_plus(text)
        text = html.unescape(text)

        if text == before:
            break

    return text


def normalize_payload(payload: str) -> str:
    text = str(payload).replace("\r\n", "\n").replace("\r", "\n")
    text = deep_decode(text.lower())

    # 값만 다른 거의 같은 HTTP 요청을 중복으로 보기 위한 일반화
    text = re.sub(r"(?im)^host:\s*.+$", "host: <host>", text)
    text = re.sub(r"(?im)^referer:\s*.+$", "referer: <referer>", text)
    text = re.sub(r"(?im)^content-length:\s*\d+\s*$", "content-length: <len>", text)

    # 자주 바뀌는 헤더 값 일반화
    text = re.sub(r"(?im)^cookie:\s*.+$", "cookie: <cookie>", text)
    text = re.sub(r"(?im)^authorization:\s*.+$", "authorization: <auth>", text)

    # 공백 정리
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n+", "\n", text)

    return text.strip()


def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"[SKIP] not found: {path}")
        return pd.DataFrame(columns=["Log_Number", "payload", "label_action"])

    df = pd.read_csv(path, encoding="utf-8-sig")

    # 혹시 label 컬럼으로 들어온 파일 대응
    if "label" in df.columns and "label_action" not in df.columns:
        df = df.rename(columns={"label": "label_action"})

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"{path} missing columns: {missing}")

    if "Log_Number" not in df.columns:
        df["Log_Number"] = range(1, len(df) + 1)

    df = df[["Log_Number", "payload", "label_action"]].copy()

    df["payload"] = df["payload"].astype(str)
    df["label_action"] = df["label_action"].astype(str).str.strip()

    df = df[df["payload"].str.strip() != ""]
    df = df[df["label_action"].str.strip() != ""]

    return df


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--base",
        default=str(DEFAULT_BASE),
        help="기존 train CSV 경로"
    )

    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help="병합 결과 저장 경로"
    )

    parser.add_argument(
        "--extra",
        nargs="*",
        default=[str(p) for p in DEFAULT_EXTRA_FILES],
        help="추가할 external CSV 파일들"
    )

    args = parser.parse_args()

    base_path = Path(args.base)
    out_path = Path(args.out)
    extra_paths = [Path(p) for p in args.extra]

    print("=" * 70)
    print("[MERGE] base:", base_path)
    print("[MERGE] extra files:")
    for p in extra_paths:
        print(" -", p)
    print("[MERGE] out:", out_path)

    base = load_csv(base_path)
    print("=" * 70)
    print("[BASE]")
    print("rows:", len(base))
    print(base["label_action"].value_counts())

    base["_norm"] = base["payload"].map(normalize_payload)
    base_norm_set = set(zip(base["label_action"], base["_norm"]))

    extra_frames = []

    for path in extra_paths:
        extra = load_csv(path)

        if extra.empty:
            continue

        before = len(extra)

        extra["_norm"] = extra["payload"].map(normalize_payload)

        # 기존 base와 같은 라벨 + 같은 정규화 payload 제거
        extra = extra[
            ~extra.apply(
                lambda r: (r["label_action"], r["_norm"]) in base_norm_set,
                axis=1
            )
        ].copy()

        # extra 내부 중복 제거
        extra = extra.drop_duplicates(subset=["label_action", "_norm"], keep="first")

        after = len(extra)

        print("=" * 70)
        print(f"[EXTRA] {path}")
        print("before:", before)
        print("after overlap/internal dedup:", after)
        print("removed:", before - after)
        print(extra["label_action"].value_counts())

        extra_frames.append(extra)

        # 이후 extra끼리도 중복되지 않도록 base_norm_set에 추가
        for _, row in extra.iterrows():
            base_norm_set.add((row["label_action"], row["_norm"]))

    if extra_frames:
        merged = pd.concat([base] + extra_frames, ignore_index=True)
    else:
        merged = base.copy()

    # 최종 전체 중복 제거
    before_final = len(merged)
    merged = merged.drop_duplicates(subset=["label_action", "_norm"], keep="first").copy()
    after_final = len(merged)

    merged = merged.drop(columns=["_norm"])
    merged["Log_Number"] = range(1, len(merged) + 1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(out_path, index=False, encoding="utf-8-sig")

    print("=" * 70)
    print("[FINAL]")
    print("before final dedup:", before_final)
    print("after final dedup:", after_final)
    print("removed final:", before_final - after_final)
    print("saved:", out_path)
    print()
    print(merged["label_action"].value_counts())


if __name__ == "__main__":
    main()