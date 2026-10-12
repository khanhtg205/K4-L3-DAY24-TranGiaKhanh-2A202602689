"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng với chuỗi băm (hash chain sha256).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi kiểm toán vào ledger với hash chain.

    Tự động tính `prev_hash` từ dòng trước và `hash` cho dòng hiện tại.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            lines = text.splitlines()
            last_line = lines[-1].strip()
            if last_line:
                try:
                    last_record = json.loads(last_line)
                    if "hash" in last_record:
                        prev_hash = last_record["hash"]
                except Exception:
                    pass

    record = dict(entry)
    record["prev_hash"] = prev_hash

    to_hash = {k: v for k, v in record.items() if k != "hash"}
    canonical_json = json.dumps(to_hash, sort_keys=True, ensure_ascii=False)
    record["hash"] = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    line = json.dumps(record, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của file ledger:
    - Mọi dòng đều có `reason` không rỗng
    - `prev_hash` khớp với hash của dòng liền trước (dòng đầu khớp '0'*64)
    - `hash` khớp với nội dung tính toán lại từ các trường của dòng đó.
    """
    path = Path(path)
    if not path.exists():
        return True

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return True

    expected_prev = "0" * 64
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Bắt buộc mọi dòng có reason không rỗng
        if not entry.get("reason"):
            return False

        # 2. Kiểm tra chuỗi liên kết prev_hash
        if entry.get("prev_hash") != expected_prev:
            return False

        # 3. Tính lại hash và so sánh với hash đã lưu
        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        to_hash = {k: v for k, v in entry.items() if k != "hash"}
        canonical_json = json.dumps(to_hash, sort_keys=True, ensure_ascii=False)
        computed_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True
