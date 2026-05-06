# 클래스별 top n-gram을 정리하고, nmap, nikto, sqlmap 같은 도구명 편향 후보를 flag 처리한다.

from __future__ import annotations

from pathlib import Path
import pandas as pd

from src.models.bundle import load_bundle
from src.utils.io import ensure_dir, write_csv


TOOL_NAMES = [
    "sqlmap", "nmap", "masscan", "nikto", "acunetix", "nessus",
    "openvas", "wpscan", "dirbuster", "gobuster", "nuclei", "hydra",
    "burp", "zap", "arachni",
]

GOOD_ATTACK_HINTS = {
    "SQL_Injection": ["union", "select", "sleep", "benchmark", "%27", "--", "or", "where", "from"],
    "Cross_Site_Scripting": ["<script", "script", "onerror", "onload", "alert", "javascript", "%3c", "document.cookie"],
    "HOST_Scan": ["port", "open", "filtered", ":80", ":443", "scan", "host"],
    "Path_Disclosure": ["../", "..\\", "passwd", "boot.ini", "web.config", ".env", "failed to open"],
    "System_Cmd_Execution": ["&&", "||", "whoami", "cmd.exe", "powershell", "wget", "curl", "$(", "uname"],
    "Vulnerability_Scan": ["cgi-bin", "phpinfo", "wp-admin", ".git", "server-status", "manager/html", "cve"],
}


def audit_top_ngrams(
    bundle_path: str | Path = "artifacts/models/inference_bundle.joblib",
    output_dir: str | Path = "outputs/analysis",
    name: str = "valid",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """bundle 안의 클래스별 top ngram을 사람이 검토하기 쉬운 표로 저장한다."""
    output_dir = ensure_dir(output_dir)
    bundle = load_bundle(bundle_path)
    top_ngrams = bundle["top_ngrams"]

    rows = []
    flag_rows = []

    for cls, data in top_ngrams.items():
        for ngram_type in ("char", "word"):
            key = f"{ngram_type}_ngrams"
            for rank, ngram in enumerate(data.get(key, []), start=1):
                flags = _audit_ngram(cls, ngram)
                row = {
                    "class": cls,
                    "type": ngram_type,
                    "rank": rank,
                    "ngram": ngram,
                    "flags": "|".join(flags),
                }
                rows.append(row)

                if flags:
                    flag_rows.append(row)

    all_df = pd.DataFrame(rows)
    flags_df = pd.DataFrame(flag_rows)

    write_csv(all_df, Path(output_dir) / f"{name}_top_ngrams_by_class.csv")
    write_csv(flags_df, Path(output_dir) / f"{name}_ngram_audit_flags.csv")

    print(f"[ngram_audit] saved:")
    print(f" - {Path(output_dir) / f'{name}_top_ngrams_by_class.csv'}")
    print(f" - {Path(output_dir) / f'{name}_ngram_audit_flags.csv'}")

    return all_df, flags_df


def _audit_ngram(cls: str, ngram: str) -> list[str]:
    flags = []
    low = str(ngram).lower()

    if any(tool in low for tool in TOOL_NAMES):
        flags.append("tool_name_bias_candidate")

    hints = GOOD_ATTACK_HINTS.get(cls, [])
    if any(h.lower() in low for h in hints):
        flags.append("attack_semantic_signal")

    if any(h in low for h in ["user-agent", "accept:", "connection:", "mozilla", "chrome"]):
        flags.append("header_or_client_bias_candidate")

    if len(low.strip()) <= 2:
        flags.append("too_short_or_generic")

    if cls in {"HOST_Scan", "Vulnerability_Scan"} and any(tool in low for tool in TOOL_NAMES):
        flags.append("scan_tool_dependency_check")

    return flags
