"""
CALM Architecture vs Codebase Validator
=======================================
Validates a Java codebase against CALM architecture JSON files using GPT-4o.

Usage:
    python main.py --source https://github.com/apache/fineract \
                   --calm fineract-system_architecture.json fineract-platform-detailed_architecture.json \
                   --output ./reports
"""

import argparse
import logging
import sys
from pathlib import Path

from scanner.java_scanner import JavaScanner
from calm_parser.calm_parser import CalmParser
from comparator.llm_comparator import LLMComparator
from reporter.report_generator import ReportGenerator
from utils.logger import setup_logger

log = setup_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a Java codebase against CALM architecture JSON files."
    )
    parser.add_argument(
        "--source", "-s",
        required=True,
        help="Local path OR GitHub URL to the Java codebase.",
    )
    parser.add_argument(
        "--calm", "-c",
        nargs="+",
        required=True,
        help="One or more CALM JSON file paths.",
    )
    parser.add_argument(
        "--output", "-o",
        default="./reports",
        help="Directory for output reports (default: ./reports).",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model to use (default: gpt-4o-mini).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Max Java files to scan (default: 500).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    log.info("=" * 60)
    log.info("CALM Architecture vs Codebase Validator")
    log.info("=" * 60)

    # ── 1. Scan codebase ──────────────────────────────────────────
    log.info(f"[1/4] Scanning codebase: {args.source}")
    scanner = JavaScanner(source=args.source, max_files=args.max_files)
    code_summary = scanner.scan()
    log.info(f"      Scanned {code_summary.total_files} Java files across "
             f"{len(code_summary.packages)} packages.")

    # ── 2. Parse CALM files ───────────────────────────────────────
    log.info(f"[2/4] Parsing {len(args.calm)} CALM file(s).")
    parser = CalmParser(calm_paths=args.calm)
    calm_summary = parser.parse()
    log.info(f"      Extracted {len(calm_summary.controls)} controls from "
             f"{len(calm_summary.nodes)} nodes.")

    # ── 3. LLM validation ─────────────────────────────────────────
    log.info(f"[3/4] Running LLM validation with {args.model}.")
    comparator = LLMComparator(model=args.model)
    validation_results = comparator.validate(code_summary, calm_summary)
    log.info(f"      Classified {len(validation_results)} controls.")

    # ── 4. Generate reports ───────────────────────────────────────
    log.info(f"[4/4] Generating reports in: {args.output}")
    reporter = ReportGenerator(output_dir=args.output)
    reporter.generate(
        validation_results=validation_results,
        code_summary=code_summary,
        calm_summary=calm_summary,
    )

    # ── Summary to stdout ─────────────────────────────────────────
    stats = {r.classification for r in validation_results}
    log.info("=" * 60)
    log.info("Validation complete.")
    for cls in ["IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "DECLARED_BUT_NOT_FOUND",
                "OVERSTATED", "INFRASTRUCTURE_LEVEL", "OPTIONAL"]:
        count = sum(1 for r in validation_results if r.classification == cls)
        if count:
            log.info(f"  {cls}: {count}")
    log.info(f"Reports saved to: {Path(args.output).resolve()}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()