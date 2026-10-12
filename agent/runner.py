"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách yêu cầu thành 2 run cách ly:
    Run A: đọc corpus qua search_docs (untrusted content).
           Chỉ trích xuất ticket ID dạng số từ TÊN FILE (ví dụ ticket-014.md -> 14).
    Run B: tra cứu customer_id từ nguồn tin cậy data/customers.json (related_tickets).
           Kiểm tra quyền OBO và PEP trước khi gọi read_customer hoặc http_post.
           Mọi lượt gọi (allow hay deny) đều được ghi nhận vào audit ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu với kiến trúc Trifecta Split, PEP và Audit Ledger."""
    ledger_file = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    agent_id = "lab24-agent"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    agent_scopes = ("search_docs", "read_customer", "http_post")

    def _log(tool: str, args: dict, classification: str, decision: str, reason: str):
        args_json = json.dumps(args, sort_keys=True, ensure_ascii=False)
        args_hash = hashlib.sha256(args_json.encode("utf-8")).hexdigest()
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool,
            "args_hash": args_hash,
            "classification": classification,
            "decision": decision,
            "reason": reason,
        }
        ledger.append(entry, ledger_file)

    # ─────────────────────────────────────────────────────────────
    # RUN A: UNTRUSTED CONTENT (Chỉ đọc corpus, trích xuất ID số)
    # ─────────────────────────────────────────────────────────────
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    _log("search_docs", {"query": message}, "internal", "allow" if allow_search else "deny", reason_search)

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Trích xuất ticket_id (int) CHỈ từ tên file (d["id"])
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # Quét phát hiện tấn công injection từ context nhưng KHÔNG lấy customer_id của attacker
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # ─────────────────────────────────────────────────────────────
    # RUN B: TRUSTED DATA STORE & EGRESS CONTROL
    # ─────────────────────────────────────────────────────────────
    collected_records: list[dict] = []

    # Suy ra customer_id từ related_tickets trong cơ sở dữ liệu nội bộ
    customers_data: list[dict] = []
    if CUSTOMERS_FILE.exists():
        try:
            customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            customers_data = []

    target_customer_ids: list[str] = []
    for c in customers_data:
        related = c.get("related_tickets", [])
        if any(tid in related for tid in ticket_ids):
            cid = c.get("customer_id")
            if cid and cid not in target_customer_ids:
                target_customer_ids.append(cid)

    # Thực hiện đọc thông tin khách hàng hợp lệ (có kiểm tra OBO và PEP)
    for cid in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)
        _log("read_customer", {"customer_id": cid}, "restricted", "allow" if allow_read else "deny", reason_read)

        if allow_read:
            try:
                rec = tools.read_customer(cid)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # Xử lý âm mưu egress (nếu prompt injection yêu cầu POST dữ liệu)
    if injected is not None:
        target_url = injected.target_url
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        _log("http_post", {"url": target_url}, "restricted", "allow" if allow_post else "deny", reason_post)

        if allow_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)
