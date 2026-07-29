"""Samsarix Policy Engine public API."""

from .engine import PolicyEngine, decide, wildcard_match
from .errors import (
    DocumentLoadError,
    PolicyEngineError,
    PolicyValidationError,
    RequestValidationError,
    ValidationError,
)
from .loader import load_policy, load_request, load_request_bytes
from .models import Decision, Effect, Policy, Request, Rule
from .validation import parse_policy, parse_request

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "DocumentLoadError",
    "Effect",
    "Policy",
    "PolicyEngine",
    "PolicyEngineError",
    "PolicyValidationError",
    "Request",
    "RequestValidationError",
    "Rule",
    "ValidationError",
    "__version__",
    "decide",
    "load_policy",
    "load_request",
    "load_request_bytes",
    "parse_policy",
    "parse_request",
    "wildcard_match",
]
