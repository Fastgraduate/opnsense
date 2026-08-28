#!/usr/bin/env python3
"""
train_combined.py (v2) -- 2-모듈 통합 파이프라인 + 균형 잡힌 통합 평가.

변경점(v1 대비):
  - 모듈 B: C=20 (정규화 최적화)
  - 통합 6클래스 평가 시 HOST_Scan/Normal(flow) 지원 수를 콘텐츠 클래스 수준으로
    다운샘플 -> 6클래스가 비슷한 support로 공정 평가 (기존 19k vs 209 불균형 해소)
  - 모듈 A 자체 F1은 전체 test로 그대로 보고(정직), 통합 지표만 균형 subsample 사용
"""
from __future__ import annotations
import argparse, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight

CONTENT = ["Cross_Site_Scripting","SQL_Injection","Path_Disclosure","System_Cmd_Execution"]
LABELS6 = ["Normal","HOST_Scan"] + CONTENT
A_BASE = ["pkts","bytes","duration","pkts_per_sec","bytes_per_sec","mean_iat","syn","fin","rst","psh"]

def a_features(df):
    p = df["pkts"].clip(lower=1)
    for c,num in [("syn_ratio","syn"),("fin_ratio","fin"),("rst_ratio","rst"),("psh_ratio","psh")]:
        df[c] = df[num]/p
    df["bytes_per_pkt"] = df["bytes"]/p
    return df[A_BASE+["syn_ratio","fin_ratio","rst_ratio","psh_ratio","bytes_per_pkt"]].replace([np.inf,-np.inf],0).fillna(0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--flow-cap", type=int, default=5000,
                    help="모듈 A 학습에 쓸 클래스별 최대 flow 수(속도/균형). 기본 5000")
    args = ap.parse_args()

    # ===== 모듈 A: flow 스캔 =====
    fl = pd.read_csv(args.flows, low_memory=False)
    fl = fl[fl["label7"].isin(["HOST_Scan","Normal"])].copy()
    fl["syn_ratio"] = fl["syn"]/fl["pkts"].clip(lower=1)
    fl = fl[~((fl.label7=="HOST_Scan") & (fl.syn_ratio<0.3))].copy()
    n = min((fl.label7=="HOST_Scan").sum(), (fl.label7=="Normal").sum(), args.flow_cap)
    fl = pd.concat([fl[fl.label7=="HOST_Scan"].sample(n,random_state=42),
                    fl[fl.label7=="Normal"].sample(n,random_state=42)], ignore_index=True)
    XA,yA = a_features(fl), fl["label7"].values
    XAtr,XAte,yAtr,yAte = train_test_split(XA,yA,test_size=0.3,stratify=yA,random_state=42)
    modA = HistGradientBoostingClassifier(max_iter=300,random_state=42)
    modA.fit(XAtr,yAtr,sample_weight=compute_sample_weight("balanced",yAtr))
    predA = modA.predict(XAte)
    print(f"[모듈 A] flow 스캔  train n={len(XAtr):,}  test n={len(XAte):,}  macro-F1={f1_score(yAte,predA,average='macro'):.4f}")

    # ===== 모듈 B: payload 콘텐츠 =====
    pl = pd.read_csv(args.payload, low_memory=False)
    pl = pl[pl["label"].isin(CONTENT+["Normal"])].copy()
    XBtr,XBte,yBtr,yBte = train_test_split(pl["payload"].astype(str),pl["label"].values,
                                        test_size=0.3,stratify=pl["label"],random_state=42)
    vec = FeatureUnion([("char",TfidfVectorizer(analyzer="char_wb",ngram_range=(3,6),min_df=2,max_features=50000,sublinear_tf=True)),
                        ("word",TfidfVectorizer(analyzer="word",ngram_range=(1,2),min_df=2,max_features=25000,sublinear_tf=True))])
    modB = LogisticRegression(solver="lbfgs",C=20.0,class_weight="balanced",max_iter=5000).fit(vec.fit_transform(XBtr),yBtr)
    predB = modB.predict(vec.transform(XBte))
    print(f"[모듈 B] payload 콘텐츠  n={len(pl):,}  macro-F1={f1_score(yBte,predB,average='macro',labels=CONTENT+['Normal']):.4f}")

    # ===== 통합 6클래스 (전 클래스 균등 support) =====
    content_per = int(np.median([np.sum(yBte==c) for c in CONTENT]))  # 클래스당 목표 test 수(~209)
    allt = np.concatenate([np.array(yAte), np.array(yBte)])
    allp = np.concatenate([predA, predB])
    rng = np.random.RandomState(42)
    keep = []
    for lab in LABELS6:
        idx = np.where(allt==lab)[0]
        keep.extend(rng.choice(idx, min(len(idx),content_per), replace=False))
    keep = np.array(keep)
    y_true, y_pred = allt[keep], allp[keep]
    print("\n"+"="*64)
    print(f"[통합 6클래스 - 균형 support]  combined macro-F1 = {f1_score(y_true,y_pred,average='macro',labels=LABELS6):.4f}")
    print(classification_report(y_true,y_pred,labels=LABELS6,digits=4))
    cm = confusion_matrix(y_true,y_pred,labels=LABELS6)
    print("confusion (rows=true):")
    print(pd.DataFrame(cm,index=[l[:9] for l in LABELS6],columns=[l[:9] for l in LABELS6]).to_string())
    print("\n주: 통합 지표는 6클래스 support를 ~%d개로 균형화해 계산(기존 HOST_Scan 19k 불균형 해소)." % content_per)
    print("   모듈 A 단독 F1은 전체 flow test 기준으로 위에 별도 보고됨.")

if __name__ == "__main__":
    main()