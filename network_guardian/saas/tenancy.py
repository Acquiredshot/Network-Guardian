from __future__ import annotations

from dataclasses import dataclass

from network_guardian.saas.auth import TokenClaims

_ROLE_ORDER = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
    "owner": 3,
}


class TenancyError(PermissionError):
    """Raised when tenant access rules are violated."""


@dataclass(frozen=True, slots=True)
class TenantContext:
    user_id: str
    organization_id: str
    role: str

    @classmethod
    def from_claims(cls, claims: TokenClaims) -> "TenantContext":
        return cls(
            user_id=claims.sub,
            organization_id=claims.org_id,
            role=claims.role,
        )


def require_org_access(context: TenantContext, organization_id: str) -> None:
    if context.organization_id != organization_id:
        raise TenancyError("Cross-tenant access denied")


def require_role(context: TenantContext, minimum_role: str) -> None:
    actual_rank = _ROLE_ORDER.get(context.role)
    required_rank = _ROLE_ORDER.get(minimum_role)
    if actual_rank is None:
        raise TenancyError(f"Unknown role: {context.role}")
    if required_rank is None:
        raise TenancyError(f"Unknown minimum role: {minimum_role}")
    if actual_rank < required_rank:
        raise TenancyError("Insufficient tenant role")
