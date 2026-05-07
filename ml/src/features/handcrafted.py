from __future__ import annotations

from collections import Counter
import math
import re
from urllib.parse import unquote

import numpy as np
import pandas as pd

from src.preprocess.normalize import normalize_text, NormalizationConfig
from src.preprocess.tokenizer import web_payload_tokenizer


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    cnt = Counter(text)
    total = len(text)
    probs = [v / total for v in cnt.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def _norm(text: str) -> str:
    return normalize_text(text, NormalizationConfig(lowercase=True, decode_rounds=2, collapse_whitespace=True))


def extract_common_features(text: str) -> dict[str, float]:
    p = _norm(text)
    tokens = web_payload_tokenizer(p)
    pct = re.findall(r"%[0-9a-fA-F]{2}", str(text))
    special = re.findall(r"[<>'\";()|&=%/\\`#?$-]", p)
    key_matches = re.findall(r"[?&]([^=&#]+)=", p)
    val_matches = re.findall(r"[?&][^=&#]+=([^&#]*)", p)

    return {
        "payload_length": len(p),
        "char_entropy": shannon_entropy(p),
        "url_encoding_ratio": len(pct) / max(len(str(text)), 1),
        "digit_ratio": sum(c.isdigit() for c in p) / max(len(p), 1),
        "special_char_ratio": len(special) / max(len(p), 1),
        "slash_count": p.count("/"),
        "token_count_regex": len(tokens),
        "unique_token_ratio": len(set(tokens)) / max(len(tokens), 1),
        "max_token_length": max([len(t) for t in tokens], default=0),
        "param_count": len(key_matches),
        "param_value_entropy": shannon_entropy("".join(val_matches)),
    }


def extract_sqli_features(text: str) -> dict[str, float]:
    p = _norm(text)
    core = re.findall(r"\b(select|union|insert|update|delete|drop|from|where|having|order\s+by|group\s+by)\b", p, flags=re.I)
    logic = re.findall(r"\b(and|or|xor|not|null)\b", p, flags=re.I)
    comment = re.findall(r"(--|#|/\*|\*/)", p)
    time_funcs = re.findall(r"\b(sleep\s*\(|benchmark\s*\(|waitfor\b|pg_sleep\s*\()", p, flags=re.I)
    tautology = int(bool(re.search(r"(\bor\b\s+1\s*=\s*1\b)|('.*'\s*=\s*'.*')", p, flags=re.I)))
    union_select = int(bool(re.search(r"\bunion\b.{0,60}\bselect\b", p, flags=re.I)))
    return {
        "sql_core_keyword_count": len(core),
        "sql_logic_keyword_count": len(logic),
        "sql_comment_token_count": len(comment),
        "sql_time_func_count": len(time_funcs),
        "sql_tautology_pattern": tautology,
        "sql_union_select_pattern": union_select,
    }


def extract_xss_features(text: str) -> dict[str, float]:
    p = _norm(text)
    return {
        "script_tag_count": len(re.findall(r"<\s*/?\s*script", p, flags=re.I)),
        "event_handler_count": len(re.findall(r"\bon[a-z]+\s*=", p, flags=re.I)),
        "js_protocol_count": len(re.findall(r"javascript\s*:", p, flags=re.I)),
        "xss_function_count": len(re.findall(r"\b(alert|prompt|confirm|eval)\s*\(", p, flags=re.I)),
        "encoded_tag_count": len(re.findall(r"(%3c|%3e|%22|%27|&#x?[0-9a-f]+;?)", str(text), flags=re.I)),
        "xss_attr_injection_count": len(re.findall(r"\b(src|href|style|onerror|onload|onclick)\s*=", p, flags=re.I)),
    }


def extract_hostscan_features(text: str) -> dict[str, float]:
    p = _norm(text)
    return {
        "ip_like_pattern_count": len(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p)),
        "port_like_token_count": len(re.findall(r":\d{2,5}\b|\bport\s*\d{1,5}\b", p, flags=re.I)),
        "scan_keyword_count": len(re.findall(r"\b(scan|nmap|masscan|open|filtered|port|host|range)\b", p, flags=re.I)),
    }


def extract_path_disclosure_features(text: str) -> dict[str, float]:
    p = _norm(text)
    sensitive = re.findall(r"(/etc/passwd|boot\.ini|web\.config|\.htaccess|\.env|/proc/self|win\.ini|shadow)", p, flags=re.I)
    traversal = re.findall(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)", str(text), flags=re.I)
    error = int(bool(re.search(r"(fatal error|warning:|include\(|fopen|failed to open stream|in /var/|stack trace)", p, flags=re.I)))
    return {
        "path_traversal_count": len(traversal),
        "sensitive_file_hit_count": len(sensitive),
        "error_pattern_match": error,
    }


def extract_cmdexec_features(text: str) -> dict[str, float]:
    p = _norm(text)
    shell_sep = re.findall(r"(&&|\|\||;|\|)", p)
    commands = re.findall(r"\b(wget|curl|chmod|whoami|uname|id|cat|bash|sh|cmd\.exe|powershell|ping|nc|netcat)\b", p, flags=re.I)
    subshell = re.findall(r"(`|\$\()", p)
    return {
        "shell_separator_count": len(shell_sep),
        "command_keyword_count": len(commands),
        "subshell_pattern_count": len(subshell),
    }


def extract_vulnscan_features(text: str) -> dict[str, float]:
    p = _norm(text)
    probe_paths = re.findall(r"(cgi-bin|phpinfo|wp-admin|wp-login|admin|\.git|\.svn|server-status|manager/html)", p, flags=re.I)
    tools = re.findall(r"\b(nikto|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|sqlmap)\b", p, flags=re.I)
    keywords = re.findall(r"\b(test|backup|debug|config|setup|install|probe|vulnerab|exploit|cve-\d{4})\b", p, flags=re.I)
    return {
        "probe_path_hit_count": len(probe_paths),
        "scanner_tool_hit_count": len(tools),
        "vuln_probe_keyword_count": len(keywords),
    }


def build_handcrafted_features(texts: pd.Series | list[str]) -> pd.DataFrame:
    rows = []
    for text in texts:
        row = {}
        row.update(extract_common_features(text))
        row.update(extract_sqli_features(text))
        row.update(extract_xss_features(text))
        row.update(extract_hostscan_features(text))
        row.update(extract_path_disclosure_features(text))
        row.update(extract_cmdexec_features(text))
        row.update(extract_vulnscan_features(text))
        rows.append(row)
    return pd.DataFrame(rows).fillna(0.0)
