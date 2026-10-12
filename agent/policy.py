"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).
Mọi quyết định (allow hay deny) đều trả về kèm `reason` không rỗng.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        try:
            return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách trước khi tool chạy.

    Returns:
        (allow: bool, reason: str) — `reason` không bao giờ rỗng.
    """
    # 1. Rule tối thiểu bắt buộc: restricted data + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return (False, "Policy deny: restricted data cannot be transmitted via egress")

    # 2. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp_str = context.expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(exp_str)
            now = datetime.now(timezone.utc)
            if exp_dt <= now:
                return (False, f"Policy deny: session expired at {context.expires_at}")
        except Exception:
            pass

    # 3. Kiểm tra định danh và phân quyền On-Behalf-Of (OBO)
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return (False, f"Policy deny: unknown principal {context.principal_id}")

        principal_info = principals[context.principal_id]
        allowed_tools = set(principal_info.get("allowed_tools", []))

        # Kiểm tra mục đích yêu cầu (purpose)
        valid_purposes = set(principal_info.get("purposes", []))
        if context.request_purpose and context.request_purpose not in valid_purposes:
            return (False, f"Policy deny: purpose {context.request_purpose} not authorized for {context.principal_id}")

        # Tính quyền hiệu lực (effective scopes)
        if context.requested_tool:
            effective_scopes = set(allowed_tools)
            if context.agent_scopes:
                effective_scopes = effective_scopes.intersection(context.agent_scopes)
            if context.delegation_depth > 0:
                effective_scopes = effective_scopes.intersection(context.parent_scopes)

            if context.requested_tool not in effective_scopes:
                return (
                    False,
                    f"Policy deny: tool {context.requested_tool} not in effective scopes for {context.principal_id}",
                )

    # 4. Cho phép khi thỏa mãn tất cả các điều kiện chính sách
    target = context.requested_tool or context.request_purpose or "action"
    return (True, f"Policy allow: authorized {target} for {context.principal_id or context.agent_owner}")
