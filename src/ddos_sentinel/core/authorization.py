"""Short-lived in-process ownership capabilities, never imported from configuration."""

from dataclasses import dataclass, field
from secrets import token_urlsafe

from ddos_sentinel.core.safety import validate_target

_ISSUER = object()


@dataclass
class LabAuthorization:
    """Issued by an owned service after it binds; revoked as that service shuts down."""

    target: str
    lab_id: str
    token: str = field(default_factory=lambda: token_urlsafe(32), repr=False)
    active: bool = True
    _issuer: object | None = field(default=None, repr=False)

    def require(self, target: str, explicit: bool) -> str:
        canonical = validate_target(target)
        if not explicit or not self.active or self._issuer is not _ISSUER:
            raise ValueError("explicit consent and a live application-owned lab are required")
        if canonical != self.target:
            raise ValueError("target is not the authorized application-owned service")
        return canonical


def issue_authorization(target: str, lab_id: str) -> LabAuthorization:
    """Internal service lifecycle hook, not a user-configurable authorization mechanism."""
    return LabAuthorization(validate_target(target), lab_id, _issuer=_ISSUER)
