"""Samsarix Policy Engine public API."""

from .artifacts import (
    ArtifactTestEvidence,
    PolicyArtifact,
    create_artifact,
    load_artifact,
    parse_artifact,
)
from .batching import BatchDecision, BatchRequest, evaluate_batch, load_batch, parse_batch
from .enforcement import ActionDenied, AuditDeliveryError, AuditEvent, guarded_call
from .engine import PolicyEngine, decide, wildcard_match
from .errors import (
    ArtifactValidationError,
    BatchValidationError,
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
    "ActionDenied",
    "ArtifactTestEvidence",
    "ArtifactValidationError",
    "AuditDeliveryError",
    "AuditEvent",
    "BatchDecision",
    "BatchRequest",
    "BatchValidationError",
    "Decision",
    "DocumentLoadError",
    "Effect",
    "Policy",
    "PolicyArtifact",
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
    "create_artifact",
    "decide",
    "evaluate_batch",
    "guarded_call",
    "load_artifact",
    "load_batch",
    "load_policy",
    "load_request",
    "load_request_bytes",
    "load_test_suite",
    "parse_artifact",
    "parse_batch",
    "parse_policy",
    "parse_request",
    "parse_test_suite",
    "run_test_suite",
    "wildcard_match",
]
