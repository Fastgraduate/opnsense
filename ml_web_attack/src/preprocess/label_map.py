from __future__ import annotations

from typing import Mapping


DEFAULT_ALIASES = {
    "0": "Normal",
    "normal": "Normal",
    "Training_Normals": "Normal",
    "System_Cmd_Excution": "System_Cmd_Execution",
    "System_Command_Execution": "System_Cmd_Execution",
    "Command_Injection": "System_Cmd_Execution",
    "XSS": "Cross_Site_Scripting",
    "SQLI": "SQL_Injection",
    "SQLi": "SQL_Injection",
    "Host_Scan": "HOST_Scan",
    "HOST_SCAN": "HOST_Scan",
    "Vulnerability_Scanning": "Vulnerability_Scan",
}


def normalize_label(value: object, aliases: Mapping[str, str] | None = None) -> str:
    label = str(value).strip()
    merged = dict(DEFAULT_ALIASES)
    if aliases:
        merged.update({str(k): str(v) for k, v in aliases.items()})
    return merged.get(label, label)
