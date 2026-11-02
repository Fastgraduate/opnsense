"""Display stored ELK inference results. No model loading or inference."""
import hashlib
import json
import math


def read(obj, path):
    if not isinstance(obj, dict):
        return None
    if path in obj:
        value = obj[path]
    else:
        value = obj
        for key in path.split('.'):
            if not isinstance(value, dict):
                return None
            value = value.get(key)
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def stored_analysis(row):
    """Read ML results that were already stored by the Logstash V32 pipeline.

    Current canonical fields written by the pipeline are:
      ml.detected_class
      ml.confidence_percent
      ml.risk_level
      final_risk

    Older field names remain as fallbacks so previously indexed documents still render.
    """
    raw = row.get('raw') or {}
    sources = [raw, row.get('messageJson') or {}, row]

    # Support a JSON event.original/message without inspecting arbitrary log text.
    for key in ('event.original', 'message'):
        value = read(raw, key)
        if isinstance(value, str) and value.lstrip().startswith('{'):
            try:
                sources.append(json.loads(value))
            except ValueError:
                pass

    def first(paths):
        for source in sources:
            for path in paths:
                value = read(source, path)
                if value is not None and value != '':
                    return value
        return None

    def number(value):
        try:
            parsed = float(value)
            return parsed if math.isfinite(parsed) else None
        except (TypeError, ValueError):
            return None

    # Exact Logstash pipeline schema first.
    prediction = first([
        'ml.detected_class',
        'detected_class',
        'final_pred',
        'ml_prediction',
        'ml.prediction',
        'ml_result.prediction',
        'prediction',
    ])
    confidence = number(first([
        'ml.confidence_percent',
        'confidence_percent',
        'detected_confidence_percent',
        'final_confidence_percent',
        'ml_confidence',
        'ml.confidence',
        'ml_result.confidence',
        'confidence',
    ]))
    ml_risk_level = first([
        'ml.risk_level',
        'ml_risk_level',
        'risk_level',
        'ml.risk.label',
    ])
    final_risk = first([
        'final_risk',
        'ml.final_risk',
        'risk_label',
        'risk.label',
    ])

    # Legacy display fields are only fallbacks. The canonical display is rebuilt
    # from detected_class/confidence_percent so the frontend always matches the
    # current Logstash contract.
    legacy_main = first([
        'main_result_display',
        'ml.main_result_display',
        'ml_result.main_result_display',
    ])
    legacy_secondary = first([
        'secondary_result_display',
        'ml.secondary_result_display',
        'ml_result.secondary_result_display',
    ])

    if prediction is None and isinstance(legacy_main, str):
        prediction = legacy_main.split('·')[0].strip()

    if prediction is not None:
        main = str(prediction)
        if confidence is not None:
            main += f' · {confidence:.1f}%'
    else:
        main = str(legacy_main or '')

    return {
        'available': bool(prediction or main),
        'prediction': str(prediction or ''),
        'detected_class': str(prediction or ''),
        'main_result_display': main,
        'secondary_result_display': str(legacy_secondary or ''),
        'show_secondary': False,
        'confidence_percent': confidence,
        'ml_risk_level': str(ml_risk_level or ''),
        'final_risk': str(final_risk or ''),
        # risk_label is retained for existing frontend callers, but now points
        # to the pipeline's final max(rule, ML) result when available.
        'risk_label': str(final_risk or ml_risk_level or ''),
        'risk_score': None,
    }


def event_identity(row):
    identity = [row.get('_index', ''), row['_id']] if row.get('_id') else {
        k: v for k, v in row.items() if k not in {'id', 'ml'}
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()


def decorate(row):
    return {**row, 'id': event_identity(row), 'ml': stored_analysis(row)}


def is_attack(row):
    ml = row['ml']
    # A stored Normal decision is distinct from a raw Suricata alert.
    if ml['available'] and ml['prediction']:
        return ml['prediction'].lower() not in {'normal', 'benign'}
    kind = str(row.get('event_type') or '').lower()
    return kind == 'alert' or bool(read(row.get('raw', {}), 'suricata.eve.alert.signature')) or bool(read(row.get('raw', {}), 'alert.signature'))
