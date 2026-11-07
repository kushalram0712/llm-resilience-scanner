"""Command-Line Interface (CLI) entry point for the AI Agent Resilience Scanner."""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import List
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from scanner.engine.evaluator import ResponseEvaluator
from scanner.engine.models import EvaluationResult, TestCase
from scanner.engine.reporter import ReportGenerator
from scanner.engine.target import TargetClient


def load_test_cases(filepath: str | Path, categories: List[str] | None = None) -> List[TestCase]:
    """Loads and validates benchmark test vectors from a JSON file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Benchmark file not found: {path}")

    raw_data = json.loads(path.read_text(encoding="utf-8"))
    cases = [TestCase(**item) for item in raw_data]

    if categories:
        normalized = {c.lower().strip() for c in categories}
        cases = [c for c in cases if c.category.value.lower() in normalized]

    return cases


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    """Parses CLI arguments with environment variable fallbacks."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="python -m scanner.cli",
        description="Automated OWASP LLM01/LLM07 Resilience & Prompt Injection Scanner",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=os.getenv("TARGET_API_URL", "http://127.0.0.1:8000/v1/chat/completions"),
        help="Target LLM chat completion endpoint URL",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.getenv("TARGET_API_KEY", ""),
        help="Bearer API key for the target endpoint",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=os.getenv("TARGET_MODEL_NAME", "gpt-4o-mini"),
        help="Model identifier sent in the request payload",
    )
    parser.add_argument(
        "--test-file",
        type=str,
        default="data/test_cases.json",
        help="Path to the JSON benchmark test suite",
    )
    parser.add_argument(
        "--canary",
        type=str,
        default=os.getenv("SCANNER_SYSTEM_CANARY", "CANARY-9942-ALPHA-SEC"),
        help="Secret canary token embedded into the system prompt",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("SCANNER_TIMEOUT_SECONDS", "15")),
        help="HTTP request timeout in seconds",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=float(os.getenv("SCANNER_RATE_LIMIT_DELAY", "0.2")),
        help="Rate-limit delay in seconds between probes",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save exported HTML and JSON audit reports",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=0.0,
        help="Exit with code 1 if Resilience Score falls below this threshold (CI/CD gate)",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    """Executes the CLI scan workflow and returns an OS exit code."""
    args = parse_args(argv)
    console = Console()

    try:
        test_cases = load_test_cases(args.test_file)
    except Exception as exc:
        console.print(f"[bold red]Error loading test suite:[/bold red] {exc}")
        return 2

    if not test_cases:
        console.print("[yellow]No test cases matched the selected criteria.[/yellow]")
        return 0

    client = TargetClient(
        api_url=args.target,
        api_key=args.api_key,
        model_name=args.model,
        timeout_seconds=args.timeout,
        rate_limit_delay=args.delay,
        system_canary=args.canary,
    )
    evaluator = ResponseEvaluator(system_canary=args.canary)
    results: List[EvaluationResult] = []

    console.print(
        f"\n[bold cyan]Starting AI Agent Resilience Scan[/bold cyan] -> [underline]{args.target}[/underline]"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running OWASP LLM vectors...", total=len(test_cases))
        for tc in test_cases:
            progress.update(task, description=f"Testing [bold]{tc.id}[/bold]: {tc.name}")
            target_resp = client.send_prompt(tc.prompt)
            eval_result = evaluator.evaluate(tc, target_resp)
            results.append(eval_result)
            progress.advance(task)

    report = ReportGenerator.build_report(
        target_url=args.target,
        model_name=args.model,
        results=results,
    )

    console.print()
    ReportGenerator.print_cli_summary(report, console=console)

    out_dir = Path(args.output_dir)
    json_path = ReportGenerator.export_json(report, out_dir / f"{report.scan_id}.json")
    html_path = ReportGenerator.export_html(report, out_dir / f"{report.scan_id}.html")

    console.print(
        f"\n[bold green]✔ Reports exported:[/bold green]\n"
        f"  • JSON: [cyan]{json_path}[/cyan]\n"
        f"  • HTML: [cyan]{html_path}[/cyan]\n"
    )

    if args.fail_under and report.resilience_score < args.fail_under:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Resilience Score ({report.resilience_score}%) "
            f"is below required threshold ({args.fail_under}%)."
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())