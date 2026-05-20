# 전처리 완료 후 외부 데이터셋을 train에 병합
import pandas as pd
import csv
from pathlib import Path


base_train = Path("data/processed/train_final.csv")
external_train = Path("data/external/http_params_train_only_for_augmentation.csv")
out_path = Path("data/processed/train_final_plus_http_params.csv")

base = pd.read_csv(base_train)
ext = pd.read_csv(external_train)

# 외부 데이터는 payload, label만 사용
ext = ext[["payload", "label"]].copy()

# 기존 train도 payload, label 컬럼이 있다고 가정
base = base[["payload", "label"]].copy()

merged = pd.concat([base, ext], ignore_index=True)

# 완전 중복 제거
merged = merged.drop_duplicates(subset=["payload", "label"])

# 클래스별 최대 6000개로 cap
target = 6000
balanced = (
    merged.groupby("label", group_keys=False)
    .apply(lambda x: x.sample(n=min(len(x), target), random_state=42))
    .reset_index(drop=True)
)

# payload 내부 줄바꿈 때문에 CSV가 깨지는 것 방지
balanced["payload"] = (
    balanced["payload"]
    .astype(str)
    .str.replace("\r\n", " ", regex=False)
    .str.replace("\n", " ", regex=False)
    .str.replace("\r", " ", regex=False)
)

balanced.to_csv(
    out_path,
    index=False,
    encoding="utf-8-sig",
    quoting=csv.QUOTE_ALL,
    escapechar="\\",
    lineterminator="\n",
)
print(balanced["label"].value_counts())
print("saved:", out_path)