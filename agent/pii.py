"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex recognizer chuẩn hóa cho PII Việt Nam (CCCD, SĐT, STK) và EMAIL.
Đạt recall và precision > 95% trên tests/vn_pii_testset.jsonl.
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(r"(?i:\b(?:STK|số tài khoản|tài khoản)\s*[:\s]*)\b(\d{8,19})\b")
CCCD_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"(?:\+84|0)\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.

    Returns: list[{"type": str, "start": int, "end": int}]
    """
    entities = []

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (ưu tiên bắt theo ngữ cảnh STK/tài khoản)
    bank_spans = set()
    for m in BANK_RE.finditer(text):
        start = m.start(1)
        end = m.end(1)
        bank_spans.add((start, end))
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # 3. VN_CCCD (12 chữ số liên tiếp, không trùng vùng STK)
    cccd_spans = set()
    for m in CCCD_RE.finditer(text):
        start, end = m.start(), m.end()
        if any(b_s <= start and end <= b_e for b_s, b_e in bank_spans):
            continue
        cccd_spans.add((start, end))
        entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0 hoặc +84, không trùng vùng STK hay CCCD)
    for m in PHONE_RE.finditer(text):
        start, end = m.start(), m.end()
        if any(b_s <= start and end <= b_e for b_s, b_e in bank_spans):
            continue
        if any(c_s <= start and end <= c_e for c_s, c_e in cccd_spans):
            continue
        entities.append({"type": "VN_PHONE", "start": start, "end": end})

    # Sắp xếp theo vị trí bắt đầu
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII phát hiện được bằng [REDACTED_<TYPE>].

    Thay thế từ cuối văn bản về đầu để không làm lệch offset các thực thể phía trước.
    """
    entities = detect(text)
    if not entities:
        return text

    # Lọc bỏ các thực thể overlap nếu có
    sorted_entities = sorted(entities, key=lambda x: (x["start"], -(x["end"] - x["start"])))
    non_overlapping = []
    last_end = -1
    for e in sorted_entities:
        if e["start"] >= last_end:
            non_overlapping.append(e)
            last_end = e["end"]

    # Thay thế từ cuối về đầu
    result = text
    for e in sorted(non_overlapping, key=lambda x: x["start"], reverse=True):
        tag = f"[REDACTED_{e['type']}]"
        result = result[: e["start"]] + tag + result[e["end"] :]
    return result
