"""Pydantic v2 data models for test vectors, scan results, and audit reports."""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels aligned with security audit standards."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class AttackCategory(str, Enum):
    """OWASP LLM vulnerability categories evaluated by the scanner."""

    DIRECT_OVERRIDE = "Direct Instruction Override"
    CANARY_EXTRACTION = "System Prompt & Canary Extraction"
    DELIMITER_HIJACKING = "Delimiter & Context Framing"
    PERSONA_MODULATION = "Roleplay & Persona Modulation"
    ENCODED_PAYLOAD = "Encoded / Obfuscated Input"


class RiskRating(str, Enum):
    """Overall posture rating based on calculated Resilience Score."""

    SAFE = "Safe"
    LOW_RISK = "Low Risk"
    MEDIUM_RISK = "Medium Risk"
    HIGH_RISK = "High Risk"
    CRITICAL_RISK = "Critical Risk"


class TestCase(BaseModel):
    """Represents a single structured synthetic test vector."""

    id: str = Field(..., description="Unique identifier (e.g., LLM01-001)")
    name: str = Field(..., description="Human-readable title of the test vector")
    category: AttackCategory = Field(..., description="Vulnerability category")
    severity: Severity = Field(..., description="Impact severity if guardrail fails")
    prompt: str = Field(..., description="Synthetic test prompt sent to the user role")
    expected_markers: List[str] = Field(
        default_factory=list,
        description="Deterministic strings or regex patterns indicating guardrail failure",
    )
    check_canary_leak: bool = Field(
        default=False,
        description="Whether to check if the secret system canary was leaked in output",
    )
    description: str = Field(..., description="Explanation of what this vector tests")


class TargetResponse(BaseModel):
    """Normalized HTTP response returned by the TargetClient."""

    status_code: int
    content: str
    latency_ms: float
    error: Optional[str] = None


class EvaluationResult(BaseModel):
    """Outcome of running a single TestCase through the Evaluator."""

    test_id: str
    test_name: str
    category: AttackCategory
    severity: Severity
    passed: bool = Field(
        ..., description="True if guardrail HELD (resilient), False if guardrail BROKE"
    )
    status_code: int
    latency_ms: float
    response_snippet: str
    failure_reason: Optional[str] = None
    refusal_detected: bool = False
    canary_leaked: bool = False


class CategoryBreakdown(BaseModel):
    """Aggregated metrics for a single AttackCategory."""

    category: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate: float


class AuditReport(BaseModel):
    """Complete executive audit report exported to CLI, JSON, and HTML."""

    scan_id: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    target_url: str
    model_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    resilience_score: float = Field(
        ..., description="Weighted resilience percentage from 0.0 to 100.0"
    )
    risk_rating: RiskRating
    category_breakdown: Dict[str, CategoryBreakdown]
    results: List[EvaluationResult]