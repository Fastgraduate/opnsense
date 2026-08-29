from __future__ import annotations
import argparse, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from sklearn.utils.class_weight import compute_sample_weight

SCAN = ["Normal","HOST_Scan","Vulnerability_Scan"]
CONTENT5 = ["Cross_Site_Scripting","SQL_Injection","Path_Disclosure","System_Cmd_Execution","Normal"]
CONTENT4 = ["Cross_Site_Scripting","SQL_Injection","Path_Disclosure","System_Cmd_Execution"]
A_FEATS = ["pkts","bytes","duration","pkts_per_sec","bytes_per_sec","mean_iat",
          "syn","fin","rst","psh","syn_ratio","src_paths","src_reqs"]
MERGE = {"Path_Disclosure":"File_Access_Attack","System_Cmd_Execution":"File_Access_Attack"}
PER = 209  # 균등 support

def build_vec():
    return FeatureUnion([("char",TfidfVectorizer(analyzer="char_wb",ngram_range=(3,6),min_df=2,max_features=50000,sublinear_tf=True)),
                        ("word",TfidfVectorizer(analyzer="word",ngram_range=(1,2),min_df=2,max_features=25000,sublinear_tf=True))])

def eval_view(yAte, predA, teB_labels, predB, content_labels, name):
    allt = np.concatenate([np.array(yAte), np.array(teB_labels)])
    allp = np.concatenate([predA, predB])
    labels = SCAN + content_labels
    rng = np.random.RandomState(42); keep=[]
    for lab in labels:
        idx = np.where(allt==lab)[0]
        if len(idx)==0: continue
        keep.extend(rng.choice(idx, min(len(idx),PER), replace=False))
    keep=np.array(keep); yt,yp = allt[keep], allp[keep]
    m = f1_score(yt,yp,average="macro",labels=labels)
    print(f"\n{'='*64}\n[{name}]  통합 macro-F1 = {m:.4f}")
    print(classification_report(yt,yp,labels=labels,digits=4))
    return m

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--scan", required=True)
    ap.add_argument("--payload", required=True)
    args=ap.parse_args()

    # ===== 모듈 A: 3-way 스캔 (한 번만 학습, 두 뷰 공용) =====
    sc=pd.read_csv(args.scan,low_memory=False)
    XA=sc[A_FEATS].replace([np.inf,-np.inf],0).fillna(0); yA=sc["label7"].values
    XAtr,XAte,yAtr,yAte=train_test_split(XA,yA,test_size=0.3,stratify=yA,random_state=42)
    modA=HistGradientBoostingClassifier(max_iter=300,random_state=42)
    modA.fit(XAtr,yAtr,sample_weight=compute_sample_weight("balanced",yAtr))
    predA=modA.predict(XAte)
    print(f"[모듈 A] 3-way 스캔  n={len(sc):,}  macro-F1={f1_score(yAte,predA,average='macro'):.4f}")

    # ===== 모듈 B: 콘텐츠 (동일 분할, 두 뷰로 라벨 매핑) =====
    pl=pd.read_csv(args.payload,low_memory=False)
    pl=pl[pl["label"].isin(CONTENT5)][["payload","label"]].copy()
    trB,teB=train_test_split(pl,test_size=0.3,stratify=pl["label"],random_state=42)

    # 뷰 1: 세밀 (원본 라벨)
    vec1=build_vec()
    clf1=LogisticRegression(solver="lbfgs",C=20,class_weight="balanced",max_iter=5000).fit(vec1.fit_transform(trB.payload.astype(str)),trB["label"])
    predB1=clf1.predict(vec1.transform(teB.payload.astype(str)))
    m7=eval_view(yAte,predA,teB["label"].values,predB1,CONTENT4,"세밀 뷰 (7클래스)")

    # 뷰 2: 견고 (Path+Cmd 통합)
    trB2=trB.copy(); teB2=teB.copy()
    trB2["label"]=trB2["label"].replace(MERGE); teB2["label"]=teB2["label"].replace(MERGE)
    vec2=build_vec()
    clf2=LogisticRegression(solver="lbfgs",C=20,class_weight="balanced",max_iter=5000).fit(vec2.fit_transform(trB2.payload.astype(str)),trB2["label"])
    predB2=clf2.predict(vec2.transform(teB2.payload.astype(str)))
    m6=eval_view(yAte,predA,teB2["label"].values,predB2,["Cross_Site_Scripting","SQL_Injection","File_Access_Attack"],"견고 뷰 (6클래스)")

    print(f"\n{'#'*64}")

if __name__=="__main__":
    main()