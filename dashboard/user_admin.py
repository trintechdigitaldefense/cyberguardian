"""Administrative helpers for tenant-scoped dashboard operator provisioning."""
from __future__ import annotations

import re
from typing import Any

import auth

_ALLOWED_ROLES = {"admin", "operator", "analyst", "viewer"}
_USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_TENANT = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def upsert_user(
    *, username: str, tenant_id: str, role: str, password: str, replace: bool = False
) -> dict[str, str]:
    username = str(username).strip()
    tenant_id = str(tenant_id).strip()
    role = str(role).strip().lower()
    if not _USERNAME.fullmatch(username):
        raise ValueError("username must be 1-64 safe identifier characters")
    if not _TENANT.fullmatch(tenant_id):
        raise ValueError("tenant_id must be 1-128 safe identifier characters")
    if role not in _ALLOWED_ROLES:
        raise ValueError("role must be one of: admin, operator, analyst, viewer")
    password_hash = auth.hash_password(password)
    credentials: dict[str, Any] = auth._read_credentials()
    users = credentials.get("users")
    if not isinstance(users, dict):
        users = {}
    if username in users and not replace:
        raise ValueError("user already exists; use --replace to rotate credentials")
    users[username] = {
        "password_hash": password_hash,
        "tenant_id": tenant_id,
        "role": role,
    }
    credentials["users"] = users
    auth._write_credentials_atomic(credentials)
    return {"username": username, "tenant_id": tenant_id, "role": role}
