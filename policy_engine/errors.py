"""Public exceptions raised by Samsarix Policy Engine."""

from __future__ import annotations


class PolicyEngineError(Exception):
    """Base class for expected policy-engine failures."""


class DocumentLoadError(PolicyEngineError):
    """Raised when a policy or request document cannot be safely loaded."""


class ValidationError(PolicyEngineError):
    """Base class for structured document validation failures."""

    def __init__(self, issues: list[str] | tuple[str, ...]):
        self.issues = tuple(issues)
        super().__init__("; ".join(self.issues))


class PolicyValidationError(ValidationError):
    """Raised when a policy document is invalid."""


class RequestValidationError(ValidationError):
    """Raised when an authorization request is invalid."""


class TestSuiteValidationError(ValidationError):
    """Raised when a policy test-suite document is invalid."""


class BatchValidationError(ValidationError):
    """Raised when a batch request document is invalid."""


class ArtifactValidationError(ValidationError):
    """Raised when artifact structure, integrity, or deployment pins do not match."""
