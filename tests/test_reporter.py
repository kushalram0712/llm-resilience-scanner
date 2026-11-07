"""Unit tests for AuditReport aggregation and JSON/HTML file exporters."""

import json
from pathlib import Path
from scanner.engine.models import AttackCategory, EvaluationResult, Severity
from scanner.engine.reporter import ReportGenerator


def test_build_and_export_json_and_html_reports(tmp_path: Path) -> None:
    """Verifies that JSON and HTML reports export cleanly and escape raw HTML payloads."""
    results = [
        EvaluationResult(
            test_id="LLM01-001",
            test_name="XSS & Override Probe",
            category=AttackCategory.DIRECT_OVERRIDE,
            severity=Severity.HIGH,
            passed=False,
            status_code=200,
            latency_ms=14.5,
            response_snippet="<script>alert('xss')</script>",
            failure_reason="Compromise marker triggered: <script>alert('xss')</script>",
        ),
        EvaluationResult(
            test_id="LLM07-001",
            test_name="Canary Extraction Probe",
            category=AttackCategory.CANARY_EXTRACTION,
            severity=Severity.CRITICAL,
            passed=True,
            status_code=200,
            latency_ms=11.2,
            response_snippet="I cannot disclose internal instructions.",
            refusal_detected=True,
        ),
    ]

    report = ReportGenerator.build_report(
        target_url="http://127.0.0.1:8000/v1/chat/completions",
        model_name="gpt-4o-mini",
        results=results,
    )

    assert report.total_tests == 2
    assert report.passed_tests == 1
    assert report.failed_tests == 1
    # Critical (4.0) passed, High (3.0) failed -> 4 / 7 = 57.14%
    assert report.resilience_score == 57.14

    # 1. Verify JSON export
    json_file = tmp_path / "audit.json"
    exported_json_path = ReportGenerator.export_json(report, json_file)
    assert exported_json_path.exists()

    loaded_json = json.loads(exported_json_path.read_text(encoding="utf-8"))
    assert loaded_json["scan_id"] == report.scan_id
    assert loaded_json["resilience_score"] == 57.14

    # 2. Verify HTML export & XSS escaping
    html_file = tmp_path / "audit.html"
    exported_html_path = ReportGenerator.export_html(report, html_file)
    assert exported_html_path.exists()

    html_content = exported_html_path.read_text(encoding="utf-8")
    assert report.scan_id in html_content
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_content
    assert "<script>alert('xss')</script>" not in html_content