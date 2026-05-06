from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re
from urllib.parse import unquote

import pandas as pd


@dataclass(slots=True)
class NormalizationConfig:
    lowercase: bool = True
    decode_rounds: int = 2
    collapse_whitespace: bool = True
    keep_newlines: bool = False
    mask_digits: bool = False
    mask_hex_literals: bool = False


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def restore_literal_newlines(text: str) -> str:
    text = safe_text(text)
    text = text.replace("\\r\\n", "\r\n")
    text = text.replace("\\n", "\n")
    return text


def recursive_url_decode(text: str, rounds: int = 2) -> str:
    out = safe_text(text)
    for _ in range(max(rounds, 0)):
        decoded = unquote(out)
        if decoded == out:
            break
        out = decoded
    return out


def normalize_text(text: str, config: NormalizationConfig | None = None) -> str:
    cfg = config or NormalizationConfig()
    out = restore_literal_newlines(safe_text(text))
    out = recursive_url_decode(out, cfg.decode_rounds)

    if cfg.lowercase:
        out = out.lower()

    if cfg.mask_hex_literals:
        out = re.sub(r"0x[0-9a-fA-F]+", "0xHEX", out)

    if cfg.mask_digits:
        out = re.sub(r"\b\d+\b", "0", out)

    if cfg.collapse_whitespace:
        if cfg.keep_newlines:
            out = re.sub(r"[\t\f\v ]+", " ", out)
            out = re.sub(r"\n+", "\n", out).strip()
        else:
            out = re.sub(r"\s+", " ", out).strip()

    return out


def split_http_payload(payload: str) -> tuple[str, str]:
    text = restore_literal_newlines(payload)
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def parse_request_line(line: str) -> dict[str, str]:
    line = safe_text(line).strip()
    m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$", line, flags=re.I)
    if not m:
        return {"request_method": "", "request_target": "", "http_version": ""}
    return {"request_method": m.group(1), "request_target": m.group(2), "http_version": m.group(3)}


def parse_http_payload(payload: str) -> dict[str, str]:
    header_block, body = split_http_payload(payload)
    lines = header_block.splitlines()
    request_line = lines[0] if lines else ""
    req = parse_request_line(request_line)

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    target = req.get("request_target", "")
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""

    headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return {
        "request_line": request_line,
        "request_method": req.get("request_method", ""),
        "request_target": target,
        "http_version": req.get("http_version", ""),
        "path_only": path,
        "query_string": query,
        "headers_text": headers_text,
        "body_text": body,
        "host_header": headers.get("Host", ""),
        "user_agent": headers.get("User-Agent", ""),
        "content_type": headers.get("Content-Type", ""),
    }


def preprocess_payload(payload: str, config: NormalizationConfig | None = None) -> dict[str, str]:
    cfg = config or NormalizationConfig()
    parsed = parse_http_payload(payload)

    payload_norm = normalize_text(payload, cfg)
    path_norm = normalize_text(parsed["path_only"], cfg)
    query_norm = normalize_text(parsed["query_string"], cfg)
    headers_norm = normalize_text(parsed["headers_text"], cfg)
    body_norm = normalize_text(parsed["body_text"], cfg)
    request_line_norm = normalize_text(parsed["request_line"], cfg)

    # TF-IDF 주입력: path/query/body/header를 합친다.
    # 공격 흔적이 User-Agent나 header에 있는 데이터도 있으므로 headers도 제외하지 않는다.
    tfidf_text = " ".join([path_norm, query_norm, body_norm, headers_norm]).strip()
    if not tfidf_text:
        tfidf_text = payload_norm

    return {
        "payload_norm": payload_norm,
        "request_line_norm": request_line_norm,
        "request_method": parsed["request_method"],
        "request_target": parsed["request_target"],
        "path_norm": path_norm,
        "query_norm": query_norm,
        "headers_norm": headers_norm,
        "body_norm": body_norm,
        "host_header": parsed["host_header"],
        "user_agent": parsed["user_agent"],
        "content_type": parsed["content_type"],
        "tfidf_text": tfidf_text,
    }


def build_preprocessed_frame(
    df: pd.DataFrame,
    payload_col: str = "payload",
    config: NormalizationConfig | None = None,
) -> pd.DataFrame:
    if payload_col not in df.columns:
        raise KeyError(f"payload column not found: {payload_col}")

    records = [preprocess_payload(x, config=config) for x in df[payload_col].fillna("").astype(str)]
    proc = pd.DataFrame(records, index=df.index)
    return pd.concat([df.reset_index(drop=True), proc.reset_index(drop=True)], axis=1)
