from __future__ import annotations

from typing import Iterable


def has_role(user_roles: Iterable[str], required: str) -> bool:
    return required in set(user_roles)


def require_any(user_roles: Iterable[str], required: list[str]) -> bool:
    s = set(user_roles)
    return any(r in s for r in required)


# roles used in this demo
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLE_OPERATOR = "operator"
