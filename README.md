# Web Attack Payload Classifier

웹 요청 payload 기반 공격 분류 실험 코드입니다.

대상 클래스는 다음 7개입니다.

- `Normal`
- `Cross_Site_Scripting`
- `HOST_Scan`
- `Path_Disclosure`
- `SQL_Injection`
- `System_Cmd_Execution`
- `Vulnerability_Scan`

핵심 구조는 다음과 같습니다.

1. ZIP/CSV 로드
2. 라벨 정규화
3. 빈 payload, 중복, 라벨 충돌 제거
4. train/valid/test 데이터셋 생성
5. HTTP payload 전처리 및 `tfidf_text` 생성
6. char TF-IDF + word TF-IDF 학습
7. 클래스별 top ngram 추출
8. 공통/공격별 규칙 피처 + class score feature 생성
9. Logistic Regression 학습
10. bundle 저장 및 평가

## 설치

```bash
pip install -r requirements.txt
```

## 1. 데이터셋 준비

원본 ZIP을 프로젝트 루트 또는 `data/raw/`에 둔 뒤 실행합니다.

```bash
python run_prepare_dataset.py --source data/raw/202506_web_data_set.Zip
```

출력:

```text
data/interim/train_clean.csv
data/interim/test_clean.csv
data/processed/train_final.csv
data/processed/valid_final.csv
data/processed/test_balanced.csv
data/processed/test_realistic.csv
```

## 2. 학습

```bash
python run_train.py
```

출력:

```text
artifacts/models/inference_bundle.joblib
outputs/reports/valid_classification_report.csv
outputs/confusion/valid_confusion_matrix.csv
outputs/error_analysis/valid_misclassified_samples.csv
```

## 3. 평가

```bash
python run_eval.py --test data/processed/test_balanced.csv --name balanced
python run_eval.py --test data/processed/test_realistic.csv --name realistic
```

## 4. 단일 payload 추론

```bash
python run_infer.py --payload "GET /index.php?id=1%27%20union%20select%201,2 HTTP/1.1"
```

## 설계 주의점

- `HOST_Scan`과 `Vulnerability_Scan`은 payload 기반에서 경계가 흐릴 수 있습니다.
- `Normal`은 반드시 포함해야 합니다. 정상 클래스가 없으면 정상 요청도 공격 중 하나로 억지 분류됩니다.
- top ngram은 반드시 train에서만 추출합니다.
- test를 이용해 vectorizer나 top ngram을 fit하면 데이터 누수입니다.
