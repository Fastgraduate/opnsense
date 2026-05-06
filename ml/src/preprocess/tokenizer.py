from __future__ import annotations

import re

# 웹 공격 문자열에서는 특수문자 자체가 정보다.
# 일반 NLP처럼 punctuation 제거를 하지 않는다.
WEB_TOKEN_PATTERN = re.compile(
    r"""
    %[0-9a-fA-F]{2} |
    </?[a-zA-Z][a-zA-Z0-9:_-]* |
    [a-zA-Z_][a-zA-Z0-9_]* |
    \d+ |
    --|/\*|\*/|\|\||&&|==|!=|<=|>= |
    [<>"'=/%;()&:#?._\\\-\|`$]
    """,
    re.VERBOSE,
)


def web_payload_tokenizer(text: str) -> list[str]:
    if text is None:
        return []
    return WEB_TOKEN_PATTERN.findall(str(text))
