"""
reporter/report_generator.py
=============================
Produces three output artefacts:
  1. audit_report.json  — full structured JSON
  2. audit_report.md    — human-readable Markdown with compliance matrix
  3. gaps.json          — only the non-IMPLEMENTED controls, sorted by risk
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from models import CalmSummary, CodeSummary, ValidationResult

log = logging.getLogger(__name__)

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CLS_EMOJI  = {
    "IMPLEMENTED":            "✅",
    "PARTIALLY_IMPLEMENTED":  "⚠️ ",
    "DECLARED_BUT_NOT_FOUND": "❌",
    "OVERSTATED":             "🔶",
    "INFRASTRUCTURE_LEVEL":   "🏗️ ",
    "OPTIONAL":               "ℹ️ ",
}
RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


class ReportGenerator:

    def __init__(self, output_dir: str = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        validation_results: list[ValidationResult],
        code_summary: CodeSummary,
        calm_summary: CalmSummary,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._write_json(validation_results, code_summary, calm_summary, ts)
        self._write_markdown(validation_results, code_summary, calm_summary, ts)
        self._write_gaps_json(validation_results, ts)

    # ── JSON ──────────────────────────────────────────────────────

    def _write_json(self, results, cs, calm, ts):
        path = self.output_dir / "audit_report.json"
        payload = {
            "generated_at":  datetime.now(tz=timezone.utc).isoformat(),
            "source":        cs.source,
            "calm_files":    calm.source_files,
            "summary": self._stats(results),
            "results":  [asdict(r) for r in results],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info(f"  JSON report  → {path}")

    # ── Gaps JSON ─────────────────────────────────────────────────

    def _write_gaps_json(self, results: list[ValidationResult], ts: str):
        gaps = [
            asdict(r) for r in results
            if r.classification not in ("IMPLEMENTED", "OPTIONAL", "INFRASTRUCTURE_LEVEL")
        ]
        gaps.sort(key=lambda g: RISK_ORDER.get(g["risk"], 99))
        path = self.output_dir / "gaps.json"
        path.write_text(json.dumps(gaps, indent=2), encoding="utf-8")
        log.info(f"  Gaps JSON    → {path}")

    # ── Markdown ──────────────────────────────────────────────────

    def _write_markdown(self, results, cs, calm, ts):
        stats = self._stats(results)
        lines: list[str] = []

        # Header
        lines += [
            "# CALM Architecture vs Codebase — Validation Report",
            f"> Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"> Source: `{cs.source}`  ",
            f"> CALM files: {', '.join(f'`{f}`' for f in calm.source_files)}",
            "",
        ]

        # Executive summary
        lines += [
            "## Executive Summary",
            "",
            f"Scanned **{cs.total_files:,} Java files** across **{len(cs.packages)} packages**.",
            f"Evaluated **{len(results)} CALM controls** declared across **{len(calm.nodes)} nodes**.",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Architecture type | {'Monolith' if cs.is_monolith else 'Microservice'} |",
            f"| CQRS detected | {'Yes' if cs.has_cqrs else 'No'} |",
            f"| Spring Security | {'Yes' if cs.has_spring_security else 'No'} |",
            f"| Kafka / Messaging | {'Yes' if cs.has_kafka else 'No'} |",
            f"| Resilience4j | {'Yes' if cs.has_resilience4j else 'No'} |",
            "",
        ]

        # Risk summary table
        lines += [
            "## Risk Summary",
            "",
            "| Classification | Count |",
            "|----------------|-------|",
        ]
        for cls in ["IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "DECLARED_BUT_NOT_FOUND",
                    "OVERSTATED", "INFRASTRUCTURE_LEVEL", "OPTIONAL"]:
            emoji = CLS_EMOJI.get(cls, "")
            lines.append(f"| {emoji} {cls} | {stats['by_classification'].get(cls, 0)} |")
        lines += [
            "",
            "| Risk Level | Count |",
            "|------------|-------|",
        ]
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            emoji = RISK_EMOJI.get(risk, "")
            count = stats["by_risk"].get(risk, 0)
            if count:
                lines.append(f"| {emoji} {risk} | {count} |")
        lines.append("")

        # Compliance matrix
        lines += [
            "## Control Compliance Matrix",
            "",
            "| Control | Node | Classification | Risk | Summary |",
            "|---------|------|----------------|------|---------|",
        ]
        sorted_results = sorted(
            results,
            key=lambda r: (RISK_ORDER.get(r.risk, 99), r.node_id),
        )
        for r in sorted_results:
            cls_e  = CLS_EMOJI.get(r.classification, "")
            risk_e = RISK_EMOJI.get(r.risk, "")
            short  = r.reasoning[:120].replace("|", "\\|") + ("…" if len(r.reasoning) > 120 else "")
            lines.append(
                f"| `{r.control_id}` | `{r.node_id}` "
                f"| {cls_e} {r.classification} "
                f"| {risk_e} {r.risk} "
                f"| {short} |"
            )
        lines.append("")

        # Detailed findings (non-IMPLEMENTED only)
        gaps = [r for r in sorted_results
                if r.classification not in ("IMPLEMENTED", "OPTIONAL")]
        if gaps:
            lines += ["## Detailed Gap Findings", ""]
            for r in gaps:
                lines += [
                    f"### {RISK_EMOJI.get(r.risk,'')} `{r.control_id}`",
                    f"**Node:** `{r.node_id}`  ",
                    f"**Classification:** {CLS_EMOJI.get(r.classification,'')} {r.classification}  ",
                    f"**Risk:** {r.risk}  ",
                    "",
                    f"**Reasoning:** {r.reasoning}",
                    "",
                ]
                if r.recommendations:
                    lines.append("**Recommendations:**")
                    for rec in r.recommendations:
                        lines.append(f"- {rec}")
                    lines.append("")
                if r.evidence.get("calm_config"):
                    cfg_str = json.dumps(r.evidence["calm_config"], indent=2)
                    lines += [
                        "<details><summary>CALM Config</summary>",
                        "",
                        f"```json\n{cfg_str}\n```",
                        "",
                        "</details>",
                        "",
                    ]

        # Remediation roadmap
        critical_high = [r for r in gaps if r.risk in ("CRITICAL", "HIGH")]
        if critical_high:
            lines += [
                "## Remediation Roadmap",
                "",
                "Ordered by risk. Address Critical and High items first.",
                "",
            ]
            for i, r in enumerate(critical_high, start=1):
                rec_text = r.recommendations[0] if r.recommendations else "See detailed findings."
                lines.append(f"{i}. **[{r.risk}]** `{r.control_id}` — {rec_text}")
            lines.append("")

        path = self.output_dir / "audit_report.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        log.info(f"  Markdown report → {path}")

    # ── Helpers ───────────────────────────────────────────────────

    def _stats(self, results: list[ValidationResult]) -> dict:
        from collections import Counter
        by_cls  = Counter(r.classification for r in results)
        by_risk = Counter(r.risk for r in results if r.classification != "IMPLEMENTED")
        return {
            "total":             len(results),
            "by_classification": dict(by_cls),
            "by_risk":           dict(by_risk),
        }
