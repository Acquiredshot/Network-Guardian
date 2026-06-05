from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any


class TokenError(ValueError):
    """Raised when a token is invalid."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    sub: str
    org_id: str
    role: str
    iss: str
    aud: str
    exp: int
    iat: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "sub": self.sub,
            "org_id": self.org_id,
            "role": self.role,
            "iss": self.iss,
            "aud": self.aud,
            "exp": self.exp,
            "iat": self.iat,
        }


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _json_dumps(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(message: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return _b64url_encode(digest)


def create_access_token(
    *,
    subject: str,
    org_id: str,
    role: str,
    secret: str,
    issuer: str,
    audience: str,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    if not secret:
        raise TokenError("JWT secret is required")
    issued_at = now if now is not None else int(time.time())
    claims = TokenClaims(
        sub=subject,
        org_id=org_id,
        role=role,
        iss=issuer,
        aud=audience,
        exp=issued_at + ttl_seconds,
        iat=issued_at,
    )
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = _b64url_encode(_json_dumps(header))
    encoded_claims = _b64url_encode(_json_dumps(claims.as_dict()))
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = _sign(signing_input, secret)
    return f"{encoded_header}.{encoded_claims}.{signature}"


def verify_access_token(
    token: str,
    *,
    secret: str,
    issuer: str,
    audience: str,
    now: int | None = None,
) -> TokenClaims:
    if not secret:
        raise TokenError("JWT secret is required")
    try:
        encoded_header, encoded_claims, signature = token.split(".", 2)
    except ValueError as exc:
        raise TokenError("Malformed token") from exc

    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    expected_signature = _sign(signing_input, secret)
    if not hmac.compare_digest(signature, expected_signature):
        raise TokenError("Invalid token signature")

    try:
        header = json.loads(_b64url_decode(encoded_header).decode("utf-8"))
        claims = json.loads(_b64url_decode(encoded_claims).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise TokenError("Malformed token payload") from exc

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise TokenError("Unsupported token header")
    if claims.get("iss") != issuer:
        raise TokenError("Invalid token issuer")
    if claims.get("aud") != audience:
        raise TokenError("Invalid token audience")

    current_time = now if now is not None else int(time.time())
    if int(claims.get("exp", 0)) <= current_time:
        raise TokenError("Token expired")

    required = ("sub", "org_id", "role", "iss", "aud", "exp", "iat")
    missing = [field for field in required if field not in claims]
    if missing:
        raise TokenError(f"Missing token claims: {', '.join(missing)}")

    return TokenClaims(
        sub=str(claims["sub"]),
        org_id=str(claims["org_id"]),
        role=str(claims["role"]),
        iss=str(claims["iss"]),
        aud=str(claims["aud"]),
        exp=int(claims["exp"]),
        iat=int(claims["iat"]),
    )


def generate_api_key(prefix: str = "ng") -> tuple[str, str]:
    raw = secrets.token_urlsafe(24)
    visible_prefix = f"{prefix}_{raw[:8]}"
    full_key = f"{visible_prefix}.{raw[8:]}"
    key_hash = hashlib.sha256(full_key.encode("utf-8")).hexdigest()
    return full_key, key_hash


def verify_api_key(key: str, expected_hash: str) -> bool:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, expected_hash)
