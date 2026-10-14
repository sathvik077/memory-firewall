"""Exception hierarchy.

Design rule (ACCEPTANCE_EVIDENCE_MATRIX red-team question 2): *no* exception may produce permissive
behaviour. Authorisation failures raise; the retrieval guard converts any unexpected exception into
an empty, fail-closed result rather than returning unguarded memory.
"""

from __future__ import annotations

__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "FirewallError",
    "GuardFailure",
    "IntegrityError",
    "NotFoundError",
    "PolicyError",
    "ValidationError",
]


class FirewallError(Exception):
    """Base class for all Memory Firewall errors."""

    status_code = 500
    code = "internal_error"


class ValidationError(FirewallError):
    status_code = 422
    code = "validation_error"


class AuthenticationError(FirewallError):
    """No valid credential was presented."""

    status_code = 401
    code = "authentication_required"


class AuthorizationError(FirewallError):
    """A valid credential was presented but lacks the required authority."""

    status_code = 403
    code = "forbidden"


class NotFoundError(FirewallError):
    """Target does not exist, or exists outside the caller's tenant.

    Deliberately indistinguishable from 'exists but forbidden' for cross-tenant targets so that a
    404/403 split cannot be used as an existence oracle (MF-07).
    """

    status_code = 404
    code = "not_found"


class ConflictError(FirewallError):
    status_code = 409
    code = "conflict"


class PolicyError(FirewallError):
    status_code = 400
    code = "policy_error"


class IntegrityError(FirewallError):
    status_code = 409
    code = "integrity_mismatch"


class GuardFailure(FirewallError):
    """Raised internally when the retrieval guard cannot prove a result is eligible."""

    status_code = 503
    code = "guard_fail_closed"
