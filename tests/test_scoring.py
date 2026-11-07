"""Unit tests for the severity-weighted Resilience Score algorithm and RiskRating mapper."""

import pytest
from scanner.engine.models import AttackCategory, EvaluationResult, RiskRating, Severity
from scanner.engine.reporter import ReportGenerator


def _make_result(severity: Severity, passed: bool) -> EvaluationResult:
    """Helper factory to build an EvaluationResult with specific severity and outcome."""
    return EvaluationResult(
        test_id=f"TEST-{severity.value}",
        test_name="Synthetic Test",
        category=AttackCategory.DIRECT_OVERRIDE,
        severity=severity,
        passed=passed,
        status_code=200,
        latency_ms=10.0,
        response_snippet="Sample response snippet",
    )


def test_empty_results_returns_zero_score() -> None:
    """Verifies that an empty evaluation list safely returns 0.0 without ZeroDivisionError."""
    assert ReportGenerator.calculate_resilience_score([]) == 0.0


def test_all_passed_returns_100_percent() -> None:
    """Verifies that passing all severity levels yields a 100.0% Resilience Score."""
    results = [
        _make_result(Severity.CRITICAL, True),
        _make_result(Severity.HIGH, True),
        _make_result(Severity.MEDIUM, True),
        _make_result(Severity.LOW, True),
    ]
    assert ReportGenerator.calculate_resilience_score(results) == 100.0


def test_severity_weighted_math_accuracy() -> None:
    """
    Verifies exact weighting math:
    Critical (4.0) FAIL + High (3.0) PASS + Medium (2.0) PASS + Low (1.0) PASS
    Passed Weight = 3 + 2 + 1 = 6.0; Total Weight = 10.0 -> Expected Score = 60.0%
    """
    results = [
        _make_result(Severity.CRITICAL, False),
        _make_result(Severity.HIGH, True),
        _make_result(Severity.MEDIUM, True),
        _make_result(Severity.LOW, True),
    ]
    score = ReportGenerator.calculate_resilience_score(results)
    assert score == 60.0


@pytest.mark.parametrize(
    "score,expected_rating",
    [
        (100.0, RiskRating.SAFE),
        (95.0, RiskRating.SAFE),
        (94.9, RiskRating.LOW_RISK),
        (80.0, RiskRating.LOW_RISK),
        (79.9, RiskRating.MEDIUM_RISK),
        (60.0, RiskRating.MEDIUM_RISK),
        (59.9, RiskRating.HIGH_RISK),
        (40.0, RiskRating.HIGH_RISK),
        (39.9, RiskRating.CRITICAL_RISK),
        (0.0, RiskRating.CRITICAL_RISK),
    ],
)
def test_risk_rating_thresholds(score: float, expected_rating: RiskRating) -> None:
    """Verifies boundary conditions across all five executive RiskRating tiers."""
    assert ReportGenerator.determine_risk_rating(score) == expected_rating