# V32-FINAL Elasticsearch ML Pipeline

이 백엔드는 `backend/ml/v32`에 포함된 팀원 V32-FINAL 모델을 사용해 Elasticsearch 문서를 주기적으로 보강합니다.

## 동작 흐름

1. 방화벽별 `log_index` (`suricata-filtered-*` 등)에서 최근 문서를 조회합니다.
2. 아직 `main_result_display`가 없는 문서 중 payload/HTTP 요청 정보가 있는 문서를 찾습니다.
3. `final_model.py`의 `FinalClassifier.predict_one()`으로 분석합니다.
4. 같은 Elasticsearch 문서에 아래 필드를 업데이트합니다.
   - `final_pred`
   - `final_confidence_percent`
   - `main_result_display`
   - `secondary_result_display`
   - `show_secondary`
   - `ml_model_version`
   - `ml_input_source`
   - `ml_pipeline_status`
5. 기존 `/event-logs`, `/security-alerts` API는 `elk_results.py`를 통해 저장된 결과를 그대로 표시합니다.

## 실행

```bat
pip install -r requirements.txt
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

기본적으로 백그라운드 파이프라인이 5초마다 실행됩니다.

## 확인 API

모델/worker 상태:

```bat
curl.exe http://127.0.0.1:8000/api/ml/model-status
```

team 방화벽(ID 2) 입력 데이터 진단:

```bat
curl.exe "http://127.0.0.1:8000/api/firewalls/2/ml-pipeline/diagnostics?lookback_minutes=180"
```

수동 1회 실행:

```bat
curl.exe -X POST "http://127.0.0.1:8000/api/firewalls/2/ml-pipeline/run" ^
-H "Content-Type: application/json" ^
-d "{\"batch_size\":100,\"lookback_minutes\":180,\"force\":false}"
```

ML 결과가 Elasticsearch에 들어갔는지 확인:

```bat
curl.exe -k -u elastic:비밀번호 ^
-H "Content-Type: application/json" ^
-X POST "https://192.168.10.148:9200/suricata-filtered-*/_count" ^
-d "{\"query\":{\"exists\":{\"field\":\"main_result_display\"}}}"
```

## 중요: payload 필요

V32-FINAL의 Stage1/Module B는 payload 기반입니다. 따라서 Suricata alert가 존재해도 raw payload나 HTTP 요청 데이터가 ELK 문서에 없으면 모델 추론은 수행하지 않습니다. 그 경우 문서는 `ml_pipeline_status=skipped`로 기록되며 이유가 `ml_skip_reason`에 저장됩니다.

진단 API에서 `suricata_alerts`는 많지만 `model_input_candidates`가 0이면 Suricata/Filebeat 쪽에서 payload 또는 HTTP 필드 수집을 추가해야 합니다.

## 환경변수

`.env.example` 참고:

- `ML_PIPELINE_ENABLED=true`
- `ML_PIPELINE_INTERVAL_SECONDS=5`
- `ML_PIPELINE_BATCH_SIZE=100`
- `ML_PIPELINE_LOOKBACK_MINUTES=180`
- `ML_PIPELINE_MARK_SKIPPED=true`
- `ML_V32_DIR=...` (모델 경로를 바꿀 때만 사용)
