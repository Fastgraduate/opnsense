# -*- coding: utf-8 -*-
from __future__ import annotations

"""V32-FINAL 7-class model: Stage1 Normal/Alert + Stage2 Flow gate + Payload classifier.

The bundled .joblib contains fitted sklearn models only. This file provides
raw-payload Stage1 feature extraction, routing, prediction, and optional retraining.
"""
import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

STAGE1_FEATURES = ['payload_length', 'char_entropy', 'url_encoding_ratio', 'special_char_ratio', 'slash_count', 'token_count_regex', 'unique_token_ratio', 'max_token_length', 'param_count', 'param_value_entropy', 'sqli_char_score', 'sqli_word_score', 'sqli_total_score', 'sql_core_keyword_count', 'sql_logic_keyword_count', 'sql_comment_token_count', 'sql_time_func_count', 'sql_tautology_pattern', 'sql_union_select_pattern', 'xss_char_score', 'xss_word_score', 'xss_total_score', 'script_tag_count', 'event_handler_count', 'js_protocol_count', 'xss_function_count', 'encoded_tag_count', 'xss_attr_injection_count', 'hostscan_word_score', 'hostscan_total_score', 'hostscan_char_score', 'scan_keyword_count', 'port_like_token_count', 'pathdisclosure_char_score', 'pathdisclosure_word_score', 'pathdisclosure_total_score', 'path_traversal_count', 'sensitive_file_hit_count', 'error_pattern_match', 'cmdexec_char_score', 'cmdexec_word_score', 'cmdexec_total_score', 'shell_separator_count', 'command_keyword_count', 'subshell_pattern_count', 'vulnscan_word_score', 'vulnscan_total_score', 'vulnscan_char_score', 'probe_path_hit_count', 'scanner_tool_hit_count', 'vuln_probe_keyword_count', 'has_host_header', 'host_header_count', 'host_is_private_ip', 'host_is_loopback', 'host_is_internal_domain', 'host_contains_port', 'scanner_user_agent_score', 'nikto_user_agent_present', 'arachni_user_agent_present', 'host_private_ip_with_scanner_ua', 'rfi_probe_with_scanner_ua', 'include_virtual_with_scanner_ua', 'method_open_with_scanner_ua', 'host_context_score', 'vuln_context_score', 'host_minus_vuln_context']
ALL_FEATURES = STAGE1_FEATURES
FLOW_FEATURES = ['pkts','bytes','duration','pkts_per_sec','bytes_per_sec','mean_iat','syn','fin','rst','psh','syn_ratio']
MODULE_B_CLASSES = ['Cross_Site_Scripting','SQL_Injection','Path_Disclosure','System_Cmd_Execution']
FULL_CLASSES = ['Normal','HOST_Scan','Vulnerability_Scan'] + MODULE_B_CLASSES

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"(?::|port[=/ _-]?)(\d{1,5})\b", re.I)

SQL_CORE_WORDS = ["select", "union", "insert", "update", "delete", "drop", "where", "from", "information_schema", "database", "table", "column"]
SQL_LOGIC_WORDS = ["or", "and", "null", "like", "sleep", "benchmark", "true", "false"]
SQL_CHAR_PATTERNS = ["'", "\"", "--", "#", "/*", "*/", "=", " or ", " and ", "%27", "%22", "%2d%2d"]

XSS_WORDS = ["script", "javascript", "document.cookie", "document.location", "window.location", "alert", "prompt", "confirm", "eval", "fromcharcode", "innerhtml"]
XSS_CHAR_PATTERNS = ["<script", "</script", "%3c", "%3e", "onerror", "onload", "onclick", "src=", "href=", "javascript:"]
XSS_EVENTS_RE = re.compile(r"\bon[a-z]{3,30}\s*=", re.I)
HTML_TAG_RE = re.compile(r"</?\s*[a-z][a-z0-9:-]*(?:\s+[^<>]*)?>", re.I)

HOSTSCAN_WORDS = ["nmap", "scan", "port", "ports", "open", "closed", "filtered", "host", "service", "syn", "connect"]
HOSTSCAN_CHAR_PATTERNS = [":80", ":443", ":22", ":21", ":25", ":8080", "open", "scan"]

PATH_WORDS = ["passwd", "shadow", "boot.ini", "win.ini", "web.config", "config", "conf", "etc", "proc", "root", "windows", "system32"]
PATH_CHAR_PATTERNS = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "..%5c", "/etc/", "boot.ini", "web.config"]
ERROR_PATTERNS = ["warning:", "fatal error", "stack trace", "traceback", "notice:", "undefined index", "permission denied", "no such file", "either_bof_or_eof"]

CMD_WORDS = ["whoami", "id", "uname", "cat", "wget", "curl", "bash", "sh", "cmd.exe", "powershell", "nc", "netcat", "ping", "nslookup", "certutil", "chmod", "python", "perl"]
CMD_CHAR_PATTERNS = ["&&", "||", ";", "|", "$(`", "$(", "`", "%3b", "%7c", "%26%26"]

VULN_WORDS = ["nikto", "arachni", "zap", "hydra", "nessus", "acunetix", "cgi-bin", "wp-admin", "phpmyadmin", "admin", "login", "test", "backup", "debug", "setup", "install"]
PROBE_PATHS = ["/admin", "/login", "/cgi-bin", "/wp-admin", "/phpmyadmin", "/server-status", "/.git", "/backup", "/config", "/setup", "/install", "/debug"]
VULN_PROBE_WORDS = ["vulnerability", "exploit", "probe", "scanner", "scan", "cve", "test", "payload"]

HOST_HEADER_RE = re.compile(r"(?im)^Host\s*:\s*([^\r\n]*)")
USER_AGENT_RE = re.compile(r"(?im)^User-Agent\s*:\s*([^\r\n]*)")
HTTP_METHOD_RE = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND)\s+", re.I)
PRIVATE_IP_RE = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)")
LOOPBACK_IP_RE = re.compile(r"^127\.")
INTERNAL_HOST_RE = re.compile(r"(?:^|\.)(?:local|internal|intranet|lan|corp|home|test|dev|admin)(?::\d+)?$", re.I)
SCANNER_UA_WORDS = ["nikto", "arachni", "nmap", "masscan", "acunetix", "nessus", "zap", "wpscan", "sqlmap"]

SPECIAL_CHARS = set("'\"<>;(){}[]|&=:/\\?%$#@!`+*,")


def safe_text(value) -> str:
    if value is None:
        return ""
    try:
        if value != value:
            return ""
    except Exception:
        pass
    return str(value)


def decode_repeated(text: str, times: int = 2) -> str:
    result = text
    for _ in range(times):
        try:
            decoded = unquote_plus(result)
        except Exception:
            break
        if decoded == result:
            break
        result = decoded
    return result


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


def count_word_hits(text: str, words: list[str]) -> int:
    return sum(len(re.findall(r"(?<![a-z0-9_])" + re.escape(w) + r"(?![a-z0-9_])", text, flags=re.I)) for w in words)


def count_substring_hits(text: str, patterns: list[str]) -> int:
    lower = text.lower()
    return sum(lower.count(p.lower()) for p in patterns)


def regex_count(pattern: str, text: str, flags=0) -> int:
    return len(re.findall(pattern, text, flags=flags))


def get_request_target(text: str) -> str:
    first_line = text.splitlines()[0] if text.splitlines() else text
    m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)", first_line, flags=re.I)
    if m:
        return m.group(2)
    return text


def extract_query_pairs(text: str):
    target = get_request_target(text)
    try:
        parts = urlsplit(target)
        query = parts.query
    except Exception:
        query = ""

    pairs = []
    if query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
        except Exception:
            pairs = []
    return query, pairs


def ratio(numer: float, denom: float) -> float:
    if denom <= 0:
        return 0.0
    return float(numer) / float(denom)


def bool_int(value: bool) -> int:
    return 1 if value else 0


def get_http_method(text: str) -> str:
    first_line = text.splitlines()[0] if text.splitlines() else text
    m = HTTP_METHOD_RE.match(first_line.strip())
    return m.group(1).upper() if m else ""


def extract_header_values(text: str, pattern: re.Pattern) -> list[str]:
    return [m.group(1).strip() for m in pattern.finditer(text)]


def host_without_port(host: str) -> str:
    host = host.strip().strip("[]")
    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            return left
    return host


def extract_features(payload: str) -> dict:
    raw = safe_text(payload)
    decoded = decode_repeated(raw, times=2)
    lower_raw = raw.lower()
    lower = decoded.lower()

    method = get_http_method(raw)
    host_values = extract_header_values(raw, HOST_HEADER_RE)
    ua_values = extract_header_values(raw, USER_AGENT_RE)
    ua_joined = " ".join(ua_values).lower()
    primary_host = host_values[0].strip() if host_values else ""
    primary_host_no_port = host_without_port(primary_host).lower()
    has_host = bool(host_values and primary_host != "")
    host_count = len(host_values)
    duplicate_host = host_count > 1
    missing_host = not host_values or primary_host == ""
    host_contains_port = bool(re.search(r":\d{1,5}$", primary_host))
    host_is_private_ip = bool(PRIVATE_IP_RE.match(primary_host_no_port))
    host_is_loopback = bool(LOOPBACK_IP_RE.match(primary_host_no_port))
    host_is_internal_domain = bool(INTERNAL_HOST_RE.search(primary_host_no_port)) or any(x in primary_host_no_port for x in ["internal", "localhost", "metadata.google.internal"])
    host_domain_like = bool(re.search(r"[a-z]", primary_host_no_port) and "." in primary_host_no_port)
    scanner_ua_score = count_substring_hits(ua_joined, SCANNER_UA_WORDS)
    nikto_present = bool_int("nikto" in ua_joined)
    arachni_present = bool_int("arachni" in ua_joined)

    length = len(raw)
    tokens = TOKEN_RE.findall(decoded)
    token_count = len(tokens)
    unique_token_count = len(set(t.lower() for t in tokens))
    token_lengths = [len(t) for t in tokens]

    query, pairs = extract_query_pairs(raw)
    param_keys = [k for k, _ in pairs]
    param_values = [v for _, v in pairs]
    joined_values = "&".join(param_values)
    joined_keys = "&".join(param_keys)

    # 공통 피처
    feats = {
        "payload_length": length,
        "char_entropy": entropy(raw),
        "url_encoding_ratio": ratio(len(URL_ENC_RE.findall(raw)), max(length, 1)),
        "special_char_ratio": ratio(sum(1 for c in raw if c in SPECIAL_CHARS), max(length, 1)),
        "slash_count": raw.count("/"),
        "token_count_regex": token_count,
        "unique_token_ratio": ratio(unique_token_count, max(token_count, 1)),
        "max_token_length": max(token_lengths) if token_lengths else 0,
        "param_count": len(pairs),
        "param_value_entropy": entropy(joined_values),
        "digit_ratio": ratio(sum(ch.isdigit() for ch in raw), max(length, 1)),
        "ampersand_count": raw.count("&"),
        "equals_count": raw.count("="),
        "question_mark_count": raw.count("?"),
        "avg_token_length": float(sum(token_lengths) / len(token_lengths)) if token_lengths else 0.0,
        "paren_count": raw.count("(") + raw.count(")"),
        "has_query_string": bool_int("?" in get_request_target(raw) or bool(query)),
        "param_key_entropy": entropy(joined_keys),
        "quote_count_single": raw.count("'"),
        "quote_count_double": raw.count('"'),
        "backtick_count": raw.count("`"),
        "angle_bracket_count": raw.count("<") + raw.count(">") + lower_raw.count("%3c") + lower_raw.count("%3e"),

        # HTTP/Host/Scanner 맥락 피처 - v2
        "http_method_get": bool_int(method == "GET"),
        "http_method_head": bool_int(method == "HEAD"),
        "http_method_post": bool_int(method == "POST"),
        "http_method_options_trace_connect": bool_int(method in {"OPTIONS", "TRACE", "CONNECT", "PROPFIND"}),
        "has_host_header": bool_int(has_host),
        "missing_host_header": bool_int(missing_host),
        "host_header_count": host_count,
        "duplicate_host_header": bool_int(duplicate_host),
        "host_is_private_ip": bool_int(host_is_private_ip),
        "host_is_loopback": bool_int(host_is_loopback),
        "host_is_internal_domain": bool_int(host_is_internal_domain),
        "host_contains_port": bool_int(host_contains_port),
        "host_value_length": len(primary_host),
        "host_domain_like": bool_int(host_domain_like),
        "scanner_user_agent_score": scanner_ua_score,
        "nikto_user_agent_present": nikto_present,
        "arachni_user_agent_present": arachni_present,
    }

    # SQL Injection
    sql_core = count_word_hits(lower, SQL_CORE_WORDS)
    sql_logic = count_word_hits(lower, SQL_LOGIC_WORDS)
    sql_comment = count_substring_hits(lower, ["--", "#", "/*", "*/", "%2d%2d"])
    sql_time = count_word_hits(lower, ["sleep", "benchmark", "pg_sleep", "waitfor", "delay"])
    sql_taut = bool_int(bool(re.search(r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", lower, flags=re.I)))
    sql_union = bool_int(bool(re.search(r"\bunion\b.{0,80}\bselect\b", lower, flags=re.I | re.S)))
    sql_hex = regex_count(r"\b0x[0-9a-f]+\b", lower, flags=re.I)
    sql_concat = count_substring_hits(lower, ["concat(", "char(", "chr(", "||", "+"])
    sql_char = count_substring_hits(lower_raw, SQL_CHAR_PATTERNS) + count_substring_hits(lower, SQL_CHAR_PATTERNS)
    sql_word = sql_core + sql_logic + sql_time
    sql_meta_count = sum(lower.count(ch) for ch in ["'", '"', "-", "#", "*", "=", "(", ")"])

    feats.update({
        "sqli_char_score": sql_char + sql_comment + sql_taut + sql_union,
        "sqli_word_score": sql_word,
        "sqli_total_score": sql_char + sql_word * 2 + sql_comment * 2 + sql_time * 3 + sql_taut * 5 + sql_union * 5 + sql_hex + sql_concat,
        "sql_core_keyword_count": sql_core,
        "sql_logic_keyword_count": sql_logic,
        "sql_comment_token_count": sql_comment,
        "sql_time_func_count": sql_time,
        "sql_tautology_pattern": sql_taut,
        "sql_union_select_pattern": sql_union,
        "sql_meta_char_ratio": ratio(sql_meta_count, max(length, 1)),
        "sql_hex_pattern_count": sql_hex,
        "sql_concat_pattern_count": sql_concat,
    })

    # XSS
    script_tag = count_substring_hits(lower, ["<script", "</script", "%3cscript", "%2fscript"])
    event_handler = len(XSS_EVENTS_RE.findall(decoded)) + regex_count(r"on(?:error|load|click|mouseover|focus|submit)%3d", lower_raw, re.I)
    js_protocol = count_substring_hits(lower, ["javascript:", "java%0ascript", "java%09script"])
    xss_func = count_word_hits(lower, ["alert", "prompt", "confirm", "eval", "settimeout", "setinterval"])
    encoded_tag = regex_count(r"%3c|%3e|&lt;|&gt;", lower_raw, flags=re.I)
    attr_injection = regex_count(r"[\"']\s*(?:on[a-z]+|src|href)\s*=", decoded, flags=re.I)
    dom_keyword = count_substring_hits(lower, ["document.", "window.", "location", "cookie", "innerhtml", "localstorage"])
    html_tags = len(HTML_TAG_RE.findall(decoded))
    xss_obfus = count_substring_hits(lower, ["fromcharcode", "unescape", "atob", "eval", "\\x", "&#x", "%u"])
    open_angles = raw.count("<") + lower_raw.count("%3c")
    close_angles = raw.count(">") + lower_raw.count("%3e")
    tag_imbalance = abs(open_angles - close_angles)
    xss_char = count_substring_hits(lower_raw, XSS_CHAR_PATTERNS) + count_substring_hits(lower, XSS_CHAR_PATTERNS)
    xss_word = count_substring_hits(lower, XSS_WORDS)

    feats.update({
        "xss_char_score": xss_char + encoded_tag + event_handler,
        "xss_word_score": xss_word,
        "xss_total_score": xss_char + xss_word * 2 + script_tag * 5 + event_handler * 4 + js_protocol * 4 + xss_func * 2 + encoded_tag + attr_injection * 3 + dom_keyword,
        "script_tag_count": script_tag,
        "event_handler_count": event_handler,
        "js_protocol_count": js_protocol,
        "xss_function_count": xss_func,
        "encoded_tag_count": encoded_tag,
        "xss_attr_injection_count": attr_injection,
        "dom_keyword_count": dom_keyword,
        "html_tag_count": html_tags,
        "html_angle_bracket_ratio": ratio(feats["angle_bracket_count"], max(length, 1)),
        "xss_obfuscation_count": xss_obfus,
        "tag_imbalance_score": tag_imbalance,
    })

    # HOST Scan
    host_word_hit = count_word_hits(lower, HOSTSCAN_WORDS)
    host_char_hits = [lower.count(p.lower()) for p in HOSTSCAN_CHAR_PATTERNS]
    host_char_hit = sum(host_char_hits)
    port_like = len([p for p in PORT_RE.findall(decoded) if 0 <= int(p) <= 65535])
    ip_like = len(IPV4_RE.findall(decoded))
    scan_keyword = count_word_hits(lower, ["nmap", "scan", "masscan", "port", "open", "filtered"])

    feats.update({
        "hostscan_word_score": host_word_hit,
        "hostscan_total_score": host_word_hit * 3 + host_char_hit + port_like * 2 + ip_like,
        "hostscan_char_score": host_char_hit + port_like,
        "scan_keyword_count": scan_keyword,
        "port_like_token_count": port_like,
        "ip_like_pattern_count": ip_like,
        "hostscan_word_hit_count": host_word_hit,
        "hostscan_char_hit_count": host_char_hit,
        "hostscan_char_max_score": max(host_char_hits) if host_char_hits else 0,
    })

    # Path Disclosure
    path_char = count_substring_hits(lower_raw, PATH_CHAR_PATTERNS) + count_substring_hits(lower, PATH_CHAR_PATTERNS)
    path_word = count_substring_hits(lower, PATH_WORDS)
    traversal = count_substring_hits(lower_raw, ["../", "..\\", "%2e%2e%2f", "..%2f", "..%5c"]) + count_substring_hits(lower, ["../", "..\\"])
    sensitive = count_substring_hits(lower, ["/etc/passwd", "/etc/shadow", "boot.ini", "win.ini", "web.config", "httpd.conf", ".env"])
    err = bool_int(any(p in lower for p in ERROR_PATTERNS))

    feats.update({
        "pathdisclosure_char_score": path_char + traversal,
        "pathdisclosure_word_score": path_word,
        "pathdisclosure_total_score": path_char + path_word * 2 + traversal * 4 + sensitive * 5 + err * 3,
        "path_traversal_count": traversal,
        "sensitive_file_hit_count": sensitive,
        "error_pattern_match": err,
    })

    # System Command Execution
    shell_sep = count_substring_hits(lower_raw, ["&&", "||", ";", "|", "%3b", "%7c", "%26%26"]) + count_substring_hits(lower, ["&&", "||", ";", "|"])
    cmd_keyword = count_substring_hits(lower, CMD_WORDS)
    subshell = count_substring_hits(lower_raw, ["$(`", "$(", "`", "%24%28"]) + count_substring_hits(lower, ["$(", "`"])
    cmd_char = count_substring_hits(lower_raw, CMD_CHAR_PATTERNS) + count_substring_hits(lower, CMD_CHAR_PATTERNS)

    feats.update({
        "cmdexec_char_score": cmd_char + shell_sep + subshell,
        "cmdexec_word_score": cmd_keyword,
        "cmdexec_total_score": cmd_char + shell_sep * 3 + cmd_keyword * 3 + subshell * 4 + feats["backtick_count"] * 2,
        "shell_separator_count": shell_sep,
        "command_keyword_count": cmd_keyword,
        "subshell_pattern_count": subshell,
    })

    # Vulnerability Scan
    vuln_word_hit = count_substring_hits(lower, VULN_WORDS)
    probe_hit = count_substring_hits(lower, PROBE_PATHS)
    scanner_hit = count_substring_hits(lower, ["nikto", "arachni", "zap", "hydra", "nessus", "acunetix", "sqlmap", "wpscan"])
    vuln_probe = count_substring_hits(lower, VULN_PROBE_WORDS)
    vuln_char_hit = count_substring_hits(lower, ["/admin", "/login", "/cgi-bin", "/wp-", ".php", ".asp", ".jsp", "?test=", "debug"])

    feats.update({
        "vulnscan_word_score": vuln_word_hit,
        "vulnscan_total_score": vuln_word_hit * 3 + probe_hit * 3 + scanner_hit * 4 + vuln_probe * 2 + vuln_char_hit,
        "vulnscan_char_score": vuln_char_hit,
        "probe_path_hit_count": probe_hit,
        "scanner_tool_hit_count": scanner_hit,
        "vuln_probe_keyword_count": vuln_probe,
        "vulnscan_word_hit_count": vuln_word_hit,
        "vulnscan_char_hit_count": vuln_char_hit,
    })

    rfi_probe = count_substring_hits(lower, ["rfiinc", "remote file", "http://cirt.net", "https://cirt.net", "filemanager", "connectors/test.html"])
    include_virtual = count_substring_hits(lower, ["include virtual", "<!--#include", "ssi", "#exec cmd"])
    method_open = count_substring_hits(lower, ["method=open", "method=open+service", "open service", "open+service"])
    has_vuln_probe_context = bool_int((probe_hit + vuln_char_hit + rfi_probe + include_virtual + method_open) > 0)
    host_context_score = (
        feats["has_host_header"] * 2
        + feats["host_is_private_ip"] * 3
        + feats["host_is_loopback"] * 2
        + feats["host_is_internal_domain"] * 2
        + feats["host_contains_port"]
        + min(scanner_ua_score, 3) * 2
        + feats["http_method_options_trace_connect"]
    )
    vuln_context_score = (
        probe_hit * 3
        + vuln_char_hit
        + rfi_probe * 4
        + include_virtual * 3
        + method_open * 3
        + scanner_hit * 2
    )

    feats.update({
        "rfi_probe_count": rfi_probe,
        "include_virtual_count": include_virtual,
        "method_open_service_count": method_open,
        "host_private_ip_with_scanner_ua": bool_int(host_is_private_ip and scanner_ua_score > 0),
        "rfi_probe_with_scanner_ua": bool_int(rfi_probe > 0 and scanner_ua_score > 0),
        "include_virtual_with_scanner_ua": bool_int(include_virtual > 0 and scanner_ua_score > 0),
        "method_open_with_scanner_ua": bool_int(method_open > 0 and scanner_ua_score > 0),
        "scanner_ua_with_vuln_probe": bool_int(scanner_ua_score > 0 and has_vuln_probe_context),
        "private_host_with_vuln_probe": bool_int(host_is_private_ip and has_vuln_probe_context),
        "host_context_score": host_context_score,
        "vuln_context_score": vuln_context_score,
        "host_minus_vuln_context": host_context_score - vuln_context_score,
    })

    # v6: HOST_Scan -> System_Cmd_Execution 오분류 완화용 strict/guard 피처
    # 기존 cmdexec_total_score는 ';', '|', 'open', 'curl' 같은 느슨한 신호에 민감할 수 있으므로,
    # 실제 OS 명령 실행 구조와 스캐너 기반 취약점 probe 문맥을 분리한다.
    strict_cmd_operator = regex_count(
        r"(?:;|&&|\|\||\|)\s*(?:whoami|id|cat|wget|curl|bash|sh|cmd\.exe|powershell|nc|netcat|uname|ls|dir|ping|nslookup|certutil|chmod|python|perl)\b",
        lower,
        flags=re.I,
    )
    strict_cmd_subshell = regex_count(
        r"\$\([^)]{0,120}(?:whoami|id|cat|wget|curl|bash|sh|cmd\.exe|powershell|uname|ls|dir)[^)]{0,120}\)|`[^`]{0,120}(?:whoami|id|cat|wget|curl|bash|sh|cmd\.exe|powershell|uname|ls|dir)[^`]{0,120}`",
        lower,
        flags=re.I,
    )
    cmd_exec_function = regex_count(
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        lower,
        flags=re.I,
    )
    real_shell_command = (
        strict_cmd_operator
        + strict_cmd_subshell
        + cmd_exec_function
        + regex_count(r"(?:/bin/(?:sh|bash)|cmd\.exe\s*/c|powershell\s+(?:-c|/c))", lower, flags=re.I)
    )
    loose_cmd_keyword = max(0, cmd_keyword - real_shell_command)
    scanner_probe_context = bool_int(scanner_ua_score > 0 and has_vuln_probe_context)
    scanner_cmd_false_positive_score = max(
        0,
        scanner_probe_context * (
            min(scanner_ua_score, 3)
            + rfi_probe * 2
            + method_open * 2
            + include_virtual
            + min(probe_hit + vuln_char_hit, 5)
        ) - real_shell_command * 2,
    )
    cmd_like_but_scanner_probe = bool_int(
        scanner_probe_context
        and real_shell_command == 0
        and (cmd_keyword > 0 or method_open > 0 or rfi_probe > 0 or include_virtual > 0)
    )
    cmdexec_strict_confidence = (
        real_shell_command * 5
        + strict_cmd_operator * 3
        + strict_cmd_subshell * 4
        + cmd_exec_function * 5
        + max(0, cmd_keyword - scanner_ua_score)
        - scanner_cmd_false_positive_score * 2
    )
    hostscan_safe_from_cmd = (
        host_context_score
        + feats["hostscan_total_score"]
        + scanner_cmd_false_positive_score
        + bool_int(host_is_private_ip and scanner_ua_score > 0) * 3
        - max(cmdexec_strict_confidence, 0)
    )

    feats.update({
        "strict_cmd_operator_count": strict_cmd_operator,
        "strict_cmd_subshell_count": strict_cmd_subshell,
        "cmd_exec_function_count": cmd_exec_function,
        "real_shell_command_count": real_shell_command,
        "loose_cmd_keyword_count": loose_cmd_keyword,
        "scanner_cmd_false_positive_score": scanner_cmd_false_positive_score,
        "cmd_like_but_scanner_probe": cmd_like_but_scanner_probe,
        "cmdexec_strict_confidence_score": cmdexec_strict_confidence,
        "cmdexec_loose_minus_strict": feats["cmdexec_total_score"] - cmdexec_strict_confidence,
        "hostscan_safe_from_cmd_score": hostscan_safe_from_cmd,
        "hostscan_minus_cmdexec_context_v2": hostscan_safe_from_cmd - feats["cmdexec_total_score"],
        "rfi_method_open_scanner_combo": bool_int(scanner_ua_score > 0 and rfi_probe > 0 and method_open > 0),
        "probe_scanner_without_strict_cmd": bool_int(scanner_probe_context and real_shell_command == 0),
        "strict_cmd_without_scanner_context": bool_int(real_shell_command > 0 and scanner_ua_score == 0),
        "cmd_keyword_without_scanner_context": cmd_keyword if scanner_ua_score == 0 else max(0, cmd_keyword - scanner_ua_score),
    })

    # v7: v6 오분류 분석 기반 guard/context 피처
    # 목표: rfiinc/method=open/Nikto/private Host 조합을 실제 OS 명령 실행으로 오해하지 않도록 하고,
    # 동시에 Host 탐색 맥락이 강한 probe를 HOST_Scan 후보로 더 강하게 표현한다.
    scanner_probe_cmd_fp_v2 = max(
        0,
        scanner_cmd_false_positive_score
        + bool_int(scanner_probe_context and real_shell_command == 0) * 3
        + bool_int(scanner_ua_score > 0 and rfi_probe > 0 and real_shell_command == 0) * 2
        + bool_int(scanner_ua_score > 0 and method_open > 0 and real_shell_command == 0) * 2
        - real_shell_command * 4,
    )
    host_cmd_fp_guard = (
        host_context_score
        + scanner_probe_cmd_fp_v2
        + bool_int(host_is_private_ip and scanner_ua_score > 0) * 4
        + bool_int(rfi_probe > 0 and method_open > 0 and scanner_ua_score > 0) * 3
        - max(cmdexec_strict_confidence, 0)
    )
    cmdexec_suppression_context = max(
        0,
        scanner_probe_cmd_fp_v2
        + host_context_score
        + min(vuln_context_score, 8)
        - real_shell_command * 5,
    )
    real_cmd_vs_probe_margin = cmdexec_strict_confidence - cmdexec_suppression_context
    hostscan_cmd_boundary_v3 = host_cmd_fp_guard - feats["cmdexec_total_score"]
    scanner_rfi_method_without_strict = bool_int(scanner_ua_score > 0 and rfi_probe > 0 and method_open > 0 and real_shell_command == 0)
    private_host_scanner_probe_without_strict = bool_int(host_is_private_ip and scanner_ua_score > 0 and has_vuln_probe_context and real_shell_command == 0)
    nikto_rfi_method_host_combo = bool_int(nikto_present and rfi_probe > 0 and method_open > 0 and has_host)
    method_open_rfi_without_strict = bool_int((method_open > 0 or rfi_probe > 0) and real_shell_command == 0 and scanner_ua_score > 0)
    cmd_keyword_as_probe_artifact = bool_int(cmd_keyword > 0 and real_shell_command == 0 and scanner_probe_context)
    host_vuln_probe_context_v2 = (
        host_context_score
        + bool_int(scanner_ua_score > 0 and has_host) * 2
        + bool_int(host_is_private_ip and has_vuln_probe_context) * 3
        + min(rfi_probe + include_virtual + method_open + probe_hit, 10)
    )
    host_recall_boost_v7 = (
        host_vuln_probe_context_v2
        + scanner_probe_cmd_fp_v2
        + feats["hostscan_total_score"]
        + ip_like
        - max(0, cmdexec_strict_confidence)
        - max(0, feats["vulnscan_total_score"] - feats["hostscan_total_score"]) * 0.25
    )
    vuln_to_host_boundary_v7 = host_vuln_probe_context_v2 - vuln_context_score
    host_vs_vuln_probe_margin_v7 = host_context_score + scanner_ua_score + bool_int(host_is_private_ip) * 2 - vuln_context_score
    hostscan_confidence_v7 = host_recall_boost_v7 + feats["hostscan_total_score"] + bool_int(has_host) * 2
    scanner_private_probe_signature_v7 = bool_int(scanner_ua_score > 0 and host_is_private_ip and has_vuln_probe_context)

    feats.update({
        "scanner_probe_cmd_false_positive_v2": scanner_probe_cmd_fp_v2,
        "host_cmd_false_positive_guard_score": host_cmd_fp_guard,
        "cmdexec_suppression_context_score": cmdexec_suppression_context,
        "real_cmd_vs_probe_margin": real_cmd_vs_probe_margin,
        "hostscan_cmd_boundary_score_v3": hostscan_cmd_boundary_v3,
        "scanner_rfi_method_without_strict_cmd": scanner_rfi_method_without_strict,
        "private_host_scanner_probe_without_strict_cmd": private_host_scanner_probe_without_strict,
        "nikto_rfi_method_host_combo": nikto_rfi_method_host_combo,
        "method_open_rfi_without_strict_cmd": method_open_rfi_without_strict,
        "cmd_keyword_as_probe_artifact": cmd_keyword_as_probe_artifact,
        "host_vuln_probe_context_score_v2": host_vuln_probe_context_v2,
        "host_recall_boost_score_v7": host_recall_boost_v7,
        "vuln_to_host_boundary_score_v7": vuln_to_host_boundary_v7,
        "host_vs_vuln_probe_margin_v7": host_vs_vuln_probe_margin_v7,
        "hostscan_confidence_score_v7": hostscan_confidence_v7,
        "scanner_private_probe_signature_v7": scanner_private_probe_signature_v7,
    })

    class_scores = [
        feats["sqli_total_score"],
        feats["xss_total_score"],
        feats["cmdexec_total_score"],
        feats["hostscan_total_score"],
        feats["pathdisclosure_total_score"],
        feats["vulnscan_total_score"],
    ]
    sorted_scores = sorted(class_scores, reverse=True)
    top = sorted_scores[0] if sorted_scores else 0
    second = sorted_scores[1] if len(sorted_scores) > 1 else 0

    feats.update({
        "top_class_score": top,
        "second_class_score": second,
        "score_margin": top - second,
        "sqli_minus_xss": feats["sqli_total_score"] - feats["xss_total_score"],
        "cmdexec_minus_path": feats["cmdexec_total_score"] - feats["pathdisclosure_total_score"],
        "hostscan_minus_vulnscan": feats["hostscan_total_score"] - feats["vulnscan_total_score"],
    })

    # 누락 방지
    for name in ALL_FEATURES:
        feats.setdefault(name, 0)

    return feats


class FinalClassifier:
    """V32-FINAL inference wrapper with human-readable confidence output.

    IMPORTANT:
    - The fitted V32 model weights and routing rules are unchanged.
    - Stage1 / Module A percentages come from sklearn ``predict_proba``.
    - Module B is LinearSVC and has no native probability. Its percentages are
      a normalized softmax view of decision margins for display/ranking only;
      they are NOT calibrated probabilities.
    """

    def __init__(self, bundle):
        self.bundle = bundle
        self.stage1 = bundle['stage1']
        self.module_a = bundle['module_a']
        self.module_b = bundle['module_b']

    @classmethod
    def load(cls, model_path):
        return cls(joblib.load(model_path))

    @staticmethod
    def _softmax(scores: np.ndarray) -> np.ndarray:
        """Stable row-wise softmax used only to display Module B confidence scores."""
        x = np.asarray(scores, dtype=float)
        if x.ndim == 1:
            x = x.reshape(1, -1)
        x = x - np.max(x, axis=1, keepdims=True)
        exp_x = np.exp(x)
        denom = np.sum(exp_x, axis=1, keepdims=True)
        return exp_x / np.where(denom == 0, 1.0, denom)

    def _stage1_predict(self, payloads: pd.Series):
        feats = pd.DataFrame([extract_features(x) for x in payloads.fillna('').astype(str)])
        X = feats[self.stage1['features']]
        model = self.stage1['model']
        classes = list(model.named_steps['clf'].classes_)
        proba = model.predict_proba(X)
        alert_ix = classes.index(1)
        normal_ix = classes.index(0)
        alert_prob = proba[:, alert_ix]
        normal_prob = proba[:, normal_ix]
        alert = alert_prob >= float(self.stage1['alert_threshold'])
        return alert, alert_prob, normal_prob

    def _module_b_details(self, payloads: pd.Series):
        """Return predictions + normalized LinearSVC decision-score shares.

        The prediction itself still comes from the original V32 model. The
        normalized shares are display scores, not calibrated probabilities.
        """
        model = self.module_b['model']
        text = payloads.fillna('').astype(str)
        pred = model.predict(text)
        scores = np.asarray(model.decision_function(text), dtype=float)
        classes = np.asarray(model.classes_, dtype=object)
        if scores.ndim == 1:
            # Defensive handling for a binary estimator. V32 Module B is 4-class.
            scores = np.column_stack([-scores, scores])
        shares = self._softmax(scores)
        top_ix = np.argmax(scores, axis=1)
        order = np.argsort(scores, axis=1)[:, ::-1]
        second_ix = order[:, 1] if scores.shape[1] > 1 else top_ix
        return pred, classes, shares, top_ix, second_ix

    def _route_alert_rows(self, df: pd.DataFrame):
        n = len(df)
        final = np.empty(n, dtype=object)
        a_pred = np.array(['Unavailable'] * n, dtype=object)
        a_conf = np.full(n, np.nan, dtype=float)
        a_probs = {
            'Non_Scan': np.full(n, np.nan, dtype=float),
            'HOST_Scan': np.full(n, np.nan, dtype=float),
            'Vulnerability_Scan': np.full(n, np.nan, dtype=float),
        }
        gate = np.zeros(n, dtype=bool)

        # Module B display arrays are always returned so predict_frame can expose
        # a consistent schema even when Module B was not run.
        b_pred = np.array(['Not_Run'] * n, dtype=object)
        b_top_conf = np.full(n, np.nan, dtype=float)
        b_second_pred = np.array(['Not_Run'] * n, dtype=object)
        b_second_conf = np.full(n, np.nan, dtype=float)
        b_probs = {c: np.full(n, np.nan, dtype=float) for c in MODULE_B_CLASSES}

        flow_available = all(c in df.columns for c in self.module_a['features'])
        if flow_available:
            X = df[self.module_a['features']].apply(pd.to_numeric, errors='coerce').fillna(0.0)
            proba = self.module_a['model'].predict_proba(X)
            classes = np.asarray(self.module_a['model'].classes_, dtype=object)
            for j, c in enumerate(classes):
                if c in a_probs:
                    a_probs[c] = proba[:, j]
            ix = np.argmax(proba, axis=1)
            a_pred = classes[ix]
            a_conf = proba[np.arange(n), ix]
            gate = (a_pred != 'Non_Scan') & (a_conf >= float(self.module_a['scan_min_confidence']))
            final[gate] = a_pred[gate]

        need_b = ~gate
        if need_b.any():
            if 'payload' not in df.columns:
                raise ValueError('payload column is required for Module B.')
            local_pos = np.where(need_b)[0]
            pred, classes, shares, top_ix, second_ix = self._module_b_details(
                df.loc[need_b, 'payload']
            )
            final[need_b] = pred
            b_pred[need_b] = pred
            for j, c in enumerate(classes):
                if c in b_probs:
                    b_probs[c][need_b] = shares[:, j]
            b_top_conf[need_b] = shares[np.arange(len(local_pos)), top_ix]
            b_second_pred[need_b] = classes[second_ix]
            b_second_conf[need_b] = shares[np.arange(len(local_pos)), second_ix]

        return (
            final, a_pred, a_conf, a_probs, gate, need_b, flow_available,
            b_pred, b_top_conf, b_second_pred, b_second_conf, b_probs,
        )

    def predict_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        if 'payload' not in df.columns:
            raise ValueError('payload column is required.')
        d = df.reset_index(drop=True).copy()
        is_alert, alert_prob, normal_prob = self._stage1_predict(d['payload'])

        out = pd.DataFrame(index=d.index)
        out['stage1_normal_percent'] = normal_prob * 100.0
        out['stage1_alert_percent'] = alert_prob * 100.0
        # Backward-compatible original column.
        out['stage1_alert_probability'] = alert_prob
        out['stage1_pred'] = np.where(is_alert, 'Alert', 'Normal')

        out['module_a_pred'] = 'Not_Run'
        out['module_a_confidence'] = np.nan
        out['module_a_non_scan_percent'] = np.nan
        out['module_a_host_scan_percent'] = np.nan
        out['module_a_vulnerability_scan_percent'] = np.nan
        out['scan_gate_fired'] = False

        out['module_b_used'] = False
        out['module_b_pred'] = 'Not_Run'
        out['module_b_xss_score_percent'] = np.nan
        out['module_b_sqli_score_percent'] = np.nan
        out['module_b_path_score_percent'] = np.nan
        out['module_b_cmdexec_score_percent'] = np.nan
        out['module_b_top_score_percent'] = np.nan
        out['module_b_second_pred'] = 'Not_Run'
        out['module_b_second_score_percent'] = np.nan

        out['final_pred'] = 'Normal'
        out['final_confidence_percent'] = normal_prob * 100.0
        out['confidence_basis'] = 'Stage1 predict_proba (Normal)'
        out['result_display'] = [f"Normal ({x:.2f}%)" for x in normal_prob * 100.0]

        if is_alert.any():
            idx = np.where(is_alert)[0]
            routed = d.iloc[idx].copy()
            (
                final, a_pred, a_conf, a_probs, gate, need_b, flow_avail,
                b_pred, b_top_conf, b_second_pred, b_second_conf, b_probs,
            ) = self._route_alert_rows(routed)

            out.loc[idx, 'module_a_pred'] = a_pred
            out.loc[idx, 'module_a_confidence'] = a_conf
            out.loc[idx, 'module_a_non_scan_percent'] = a_probs['Non_Scan'] * 100.0
            out.loc[idx, 'module_a_host_scan_percent'] = a_probs['HOST_Scan'] * 100.0
            out.loc[idx, 'module_a_vulnerability_scan_percent'] = a_probs['Vulnerability_Scan'] * 100.0
            out.loc[idx, 'scan_gate_fired'] = gate
            out.loc[idx, 'module_b_used'] = need_b
            out.loc[idx, 'module_b_pred'] = b_pred
            out.loc[idx, 'module_b_xss_score_percent'] = b_probs['Cross_Site_Scripting'] * 100.0
            out.loc[idx, 'module_b_sqli_score_percent'] = b_probs['SQL_Injection'] * 100.0
            out.loc[idx, 'module_b_path_score_percent'] = b_probs['Path_Disclosure'] * 100.0
            out.loc[idx, 'module_b_cmdexec_score_percent'] = b_probs['System_Cmd_Execution'] * 100.0
            out.loc[idx, 'module_b_top_score_percent'] = b_top_conf * 100.0
            out.loc[idx, 'module_b_second_pred'] = b_second_pred
            out.loc[idx, 'module_b_second_score_percent'] = b_second_conf * 100.0
            out.loc[idx, 'final_pred'] = final

            # Final display confidence follows the component that actually made
            # the final decision. This deliberately avoids inventing a fake
            # calibrated 7-class probability.
            for local_i, global_i in enumerate(idx):
                if gate[local_i]:
                    pct = float(a_conf[local_i] * 100.0)
                    out.at[global_i, 'final_confidence_percent'] = pct
                    out.at[global_i, 'confidence_basis'] = 'Module A predict_proba'
                    out.at[global_i, 'result_display'] = f"{final[local_i]} ({pct:.2f}%)"
                else:
                    pct = float(b_top_conf[local_i] * 100.0)
                    out.at[global_i, 'final_confidence_percent'] = pct
                    out.at[global_i, 'confidence_basis'] = 'Module B normalized LinearSVC decision score (not calibrated probability)'
                    out.at[global_i, 'result_display'] = f"{final[local_i]} ({pct:.2f}%)"

        # Simplified dashboard output. Keep all detailed columns above for
        # compatibility, but expose only one main result and (when useful) one
        # runner-up candidate for the UI. The model/routing itself is unchanged.
        secondary_show_below = 85.0

        out['detected_class'] = out['final_pred']
        out['detected_confidence_percent'] = out['final_confidence_percent']
        out['secondary_class'] = ''
        out['secondary_confidence_percent'] = np.nan
        out['show_secondary'] = False
        out['main_result_display'] = ''
        out['secondary_result_display'] = ''

        for i in out.index:
            primary = str(out.at[i, 'final_pred'])
            primary_pct = float(out.at[i, 'final_confidence_percent'])
            out.at[i, 'main_result_display'] = f"{primary} · {primary_pct:.1f}%"

            # A clean Normal decision is intentionally shown alone.
            if primary == 'Normal' or primary_pct >= secondary_show_below:
                continue

            candidates = {}
            if bool(out.at[i, 'scan_gate_fired']):
                candidates = {
                    'Non_Scan': out.at[i, 'module_a_non_scan_percent'],
                    'HOST_Scan': out.at[i, 'module_a_host_scan_percent'],
                    'Vulnerability_Scan': out.at[i, 'module_a_vulnerability_scan_percent'],
                }
            elif bool(out.at[i, 'module_b_used']):
                candidates = {
                    'Cross_Site_Scripting': out.at[i, 'module_b_xss_score_percent'],
                    'SQL_Injection': out.at[i, 'module_b_sqli_score_percent'],
                    'Path_Disclosure': out.at[i, 'module_b_path_score_percent'],
                    'System_Cmd_Execution': out.at[i, 'module_b_cmdexec_score_percent'],
                }

            valid = []
            for name, val in candidates.items():
                if name == primary or pd.isna(val):
                    continue
                valid.append((name, float(val)))

            if valid:
                second_name, second_pct = max(valid, key=lambda x: x[1])
                out.at[i, 'secondary_class'] = second_name
                out.at[i, 'secondary_confidence_percent'] = second_pct
                out.at[i, 'show_secondary'] = True
                out.at[i, 'secondary_result_display'] = f"2순위 {second_name} · {second_pct:.1f}%"

        # One ready-to-render string. If confidence >= 85%, only the main result
        # is shown. If it is lower, exactly one runner-up is appended.
        out['result_display'] = out['main_result_display']
        mask = out['show_secondary']
        out.loc[mask, 'result_display'] = (
            out.loc[mask, 'main_result_display'] + '  |  ' +
            out.loc[mask, 'secondary_result_display']
        )
        return out

    def predict_one(self, payload: str, flow: dict | None = None):
        row = {'payload': payload}
        if flow:
            row.update(flow)
        return self.predict_frame(pd.DataFrame([row])).iloc[0].to_dict()

    def score_summary(self):
        return self.bundle.get('metrics', {})



def _resolve_default_model() -> Path:
    here = Path(__file__).resolve().parent
    candidates = [
        here / 'ttp_v32_final_7class_bundle.joblib',
        here / 'models' / 'ttp_v32_final_7class_bundle.joblib',
        here.parent / 'models' / 'ttp_v32_final_7class_bundle.joblib',
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def main():
    ap = argparse.ArgumentParser(description='V32-FINAL hierarchical 7-class inference')
    ap.add_argument('--model', default=str(_resolve_default_model()))
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('predict', help='Predict a CSV containing payload and optional flow columns.')
    p.add_argument('--csv', required=True)
    p.add_argument('--out', required=True)
    sub.add_parser('scores', help='Print frozen validation metadata embedded in the bundle.')
    o = sub.add_parser('one', help='Predict one payload. Flow JSON is optional.')
    o.add_argument('--payload', required=True)
    o.add_argument('--flow-json', default=None)
    args = ap.parse_args()

    clf = FinalClassifier.load(args.model)
    if args.cmd == 'scores':
        print(json.dumps(clf.score_summary(), ensure_ascii=False, indent=2))
        return
    if args.cmd == 'one':
        flow = json.loads(args.flow_json) if args.flow_json else None
        print(json.dumps(clf.predict_one(args.payload, flow), ensure_ascii=False, indent=2, default=float))
        return
    df = pd.read_csv(args.csv)
    pred = clf.predict_frame(df)
    out = pd.concat([df.reset_index(drop=True), pred], axis=1)
    out.to_csv(args.out, index=False, encoding='utf-8-sig')
    print(args.out)


if __name__ == '__main__':
    main()
