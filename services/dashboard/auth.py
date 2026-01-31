from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

import jwt
from passlib.context import CryptContext


# bcrypt has occasional backend/version friction in slim images; pbkdf2_sha256 is
# stable and sufficient for this demo.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

JWT_SECRET = os.environ.get("DASHBOARD_JWT_SECRET", "dev-secret-change-me")
JWT_ISSUER = os.environ.get("DASHBOARD_JWT_ISSUER", "kakveda-dashboard")
JWT_TTL_MINUTES = int(os.environ.get("DASHBOARD_JWT_TTL_MINUTES", "720"))


@dataclass(frozen=True)
class TokenPayload:
    sub: str  # email
    roles: list[str]
    exp: datetime
    jti: str | None = None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(email: str, roles: Iterable[str]) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_TTL_MINUTES)

    jti = secrets.token_urlsafe(16)

    payload = {
        "iss": JWT_ISSUER,
        "sub": email,
        "roles": list(sorted(set(roles))),
        "iat": int(now.timestamp()),
        "jti": jti,
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_access_token(token: str) -> TokenPayload:
    data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
    exp = datetime.fromtimestamp(int(data["exp"]), tz=timezone.utc)
    return TokenPayload(sub=str(data["sub"]), roles=list(data.get("roles") or []), exp=exp, jti=data.get("jti"))


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)
