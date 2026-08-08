"""Samsarix Policy Engine public API."""

from .engine import PolicyEngine, decide, wildcard_match
from .errors import (
    DocumentLoadError,
    PolicyEngineError,
    PolicyValidationError,
    RequestValidationError,
    TestSuiteValidationError,
    ValidationError,
)
from .loader import load_policy, load_request, load_request_bytes
from .models import Decision, Effect, Policy, Request, Rule
from .testing import (
    PolicyTestCase,
    PolicyTestExpectation,
    PolicyTestReport,
    PolicyTestResult,
    PolicyTestSuite,
    load_test_suite,
    parse_test_suite,
    run_test_suite,
)
from .validation import parse_policy, parse_request

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "DocumentLoadError",
    "Effect",
    "Policy",
    "PolicyEngine",
    "PolicyEngineError",
    "PolicyTestCase",
    "PolicyTestExpectation",
    "PolicyTestReport",
    "PolicyTestResult",
    "PolicyTestSuite",
    "PolicyValidationError",
    "Request",
    "RequestValidationError",
    "Rule",
    "TestSuiteValidationError",
    "ValidationError",
    "__version__",
    "decide",
    "load_policy",
    "load_request",
    "load_request_bytes",
    "load_test_suite",
    "parse_policy",
    "parse_request",
    "parse_test_suite",
    "run_test_suite",
    "wildcard_match",
]
