"""
comparator/llm_comparator.py
=============================
Uses GPT-4o (via openai>=1.0.0) to classify each CALM control against
the extracted code summary.

Key design decisions:
  - Never sends raw source code to the LLM.
  - Sends structured JSON summaries only.
  - Processes controls in chunks to respect context limits.
  - Uses temperature=0 for deterministic output.
  - Parses and validates JSON output from the LLM.


  # Replace openai client with anthropic client
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=4096,
    system=SYSTEM_PROMPT,
    messages=[{"role": "user", "content": user_message}]
)
raw = response.content[0].text
"""

from __future__ import annotations

import json
import logging
import os
import textwrap
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from models import (
    CLASSIFICATION_VALUES,
    RISK_VALUES,
    CalmControl,
    CalmSummary,
    CodeSummary,
    ValidationResult,
)

load_dotenv()
log = logging.getLogger(__name__)

CHUNK_SIZE = 8          # controls per LLM call
MAX_CLASSES_IN_PROMPT = 15


# ── System prompt ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
You are a senior software security architect performing an automated compliance audit.

You will receive:
1. A CODE SUMMARY — structural metadata extracted from a Java codebase (no raw source code).
2. A list of CALM CONTROLS — architectural controls declared in a CALM architecture JSON file.

Your task: for each control, determine whether it is actually implemented in the codebase.

Classification rules:
- IMPLEMENTED             : Strong code-level evidence exists (classes, annotations, imports).
- PARTIALLY_IMPLEMENTED   : Some evidence exists but coverage is incomplete or config is missing.
- DECLARED_BUT_NOT_FOUND  : Control is declared in CALM but no code evidence found.
- OVERSTATED              : The CALM claim is stronger than what the code supports.
- INFRASTRUCTURE_LEVEL    : Cannot be validated from application code — belongs to infra/deployment.
- OPTIONAL                : Control is optional and absence is not a risk.

Risk rules (when not IMPLEMENTED):
- CRITICAL : Security-critical control with no evidence (e.g., authentication, encryption).
- HIGH     : Important control absent or overstated (e.g., rate limiting, RBAC, audit logging).
- MEDIUM   : Partial implementation or ambiguous evidence.
- LOW      : Infrastructure-level or optional controls.

Output format — respond ONLY with a valid JSON array. No markdown, no explanation outside JSON.
Each element must have exactly these keys:
  control_id, classification, risk, reasoning, recommendations (array of strings)

Example element:
{
  "control_id": "fineract-api-gateway/api-rate-limiting",
  "classification": "DECLARED_BUT_NOT_FOUND",
  "risk": "HIGH",
  "reasoning": "CALM declares Resilience4j RateLimiter but no RateLimiter classes or @RateLimiter annotations found in scan.",
  "recommendations": ["Add Resilience4j RateLimiter configuration to the API gateway layer.", "Annotate rate-limited endpoints with @RateLimiter."]
}
""").strip()


class LLMComparator:
    """
    Sends structured summaries to GPT-4o and returns ValidationResult objects.
    """

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY not set. Add it to your .env file or environment."
            )
        self.client = OpenAI(api_key=api_key)
        self.model  = model

    # ── Public API ────────────────────────────────────────────────

    def validate(
        self,
        code_summary: CodeSummary,
        calm_summary: CalmSummary,
    ) -> list[ValidationResult]:
        code_ctx  = self._build_code_context(code_summary)
        controls  = calm_summary.controls
        results: list[ValidationResult] = []

        chunks = [controls[i: i + CHUNK_SIZE] for i in range(0, len(controls), CHUNK_SIZE)]
        log.info(f"Processing {len(controls)} controls in {len(chunks)} chunk(s).")

        for idx, chunk in enumerate(chunks, start=1):
            log.info(f"  LLM call {idx}/{len(chunks)} ({len(chunk)} controls) …")
            llm_results = self._call_llm(code_ctx, chunk)
            # Merge with CALM metadata to produce full ValidationResult objects
            ctrl_map = {c.control_id: c for c in chunk}
            for lr in llm_results:
                ctrl = ctrl_map.get(lr.get("control_id", ""))
                results.append(self._build_result(lr, ctrl))

        return results

    # ── Private helpers ───────────────────────────────────────────

    def _build_code_context(self, cs: CodeSummary) -> dict[str, Any]:
        """Build a lean, token-efficient code summary dict for the LLM prompt."""
        return {
            "source": cs.source,
            "total_java_files": cs.total_files,
            "top_packages": cs.packages[:30],
            "architecture_type": (
                "microservice" if cs.is_microservice else "monolith"
            ),
            "detected_patterns": {
                "spring_boot":          cs.has_spring_boot,
                "spring_security":      cs.has_spring_security,
                "oauth2":               cs.has_oauth2,
                "jwt":                  cs.has_jwt,
                "mfa":                  cs.has_mfa,
                "rbac":                 cs.has_rbac,
                "cqrs":                 cs.has_cqrs,
                "kafka":                cs.has_kafka,
                "jpa":                  cs.has_jpa,
                "batch_jobs":           cs.has_batch,
                "resilience4j":         cs.has_resilience4j,
                "rate_limiter":         cs.has_rate_limiter,
                "circuit_breaker":      cs.has_circuit_breaker,
                "audit_logging":        cs.has_audit_logging,
                "tls_config":           cs.has_tls_config,
                "input_validation":     cs.has_input_validation,
                "transaction_mgmt":     cs.has_transaction_management,
            },
            "key_classes": {
                "rest_controllers":    cs.rest_controllers[:MAX_CLASSES_IN_PROMPT],
                "security_classes":    cs.security_classes[:MAX_CLASSES_IN_PROMPT],
                "audit_classes":       cs.audit_classes[:MAX_CLASSES_IN_PROMPT],
                "command_handlers":    cs.command_handlers[:MAX_CLASSES_IN_PROMPT],
                "query_handlers":      cs.query_handlers[:MAX_CLASSES_IN_PROMPT],
                "batch_classes":       cs.batch_classes[:MAX_CLASSES_IN_PROMPT],
                "kafka_classes":       cs.kafka_classes[:MAX_CLASSES_IN_PROMPT],
                "resilience_classes":  cs.resilience_classes[:MAX_CLASSES_IN_PROMPT],
                "validation_classes":  cs.validation_classes[:MAX_CLASSES_IN_PROMPT],
            },
            "top_annotations": dict(
                list(cs.all_annotations.items())[:40]
            ),
        }

    def _build_controls_payload(self, controls: list[CalmControl]) -> list[dict]:
        return [
            {
                "control_id":    c.control_id,
                "node_id":       c.node_id,
                "node_name":     c.node_name,
                "node_type":     c.node_type,
                "description":   c.description,
                "config":        c.config,
            }
            for c in controls
        ]

    def _call_llm(self, code_ctx: dict, controls: list[CalmControl]) -> list[dict]:
        user_message = json.dumps(
            {
                "code_summary": code_ctx,
                "calm_controls": self._build_controls_payload(controls),
            },
            indent=2,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_message},
                ],
            )
            raw = response.choices[0].message.content or "{}"
            parsed = json.loads(raw)

            # GPT sometimes wraps the array in a key
            if isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, list):
                        return v
                return []
            return parsed if isinstance(parsed, list) else []

        except Exception as exc:
            log.error(f"LLM call failed: {exc}")
            # Return safe fallback results
            return [
                {
                    "control_id":      c.control_id,
                    "classification":  "INFRASTRUCTURE_LEVEL",
                    "risk":            "LOW",
                    "reasoning":       f"LLM call failed: {exc}",
                    "recommendations": [],
                }
                for c in controls
            ]

    def _build_result(
        self,
        llm_result: dict,
        ctrl: CalmControl | None,
    ) -> ValidationResult:
        classification = llm_result.get("classification", "INFRASTRUCTURE_LEVEL")
        if classification not in CLASSIFICATION_VALUES:
            classification = "INFRASTRUCTURE_LEVEL"

        risk = llm_result.get("risk", "LOW")
        if risk not in RISK_VALUES:
            risk = "MEDIUM"

        return ValidationResult(
            control_id    = llm_result.get("control_id", ctrl.control_id if ctrl else "unknown"),
            node_id       = ctrl.node_id   if ctrl else "unknown",
            control_name  = ctrl.description if ctrl else llm_result.get("control_id", ""),
            declared      = True,
            classification = classification,
            risk          = risk,
            reasoning     = llm_result.get("reasoning", ""),
            evidence={
                "calm_config":       ctrl.config if ctrl else {},
                "requirement_url":   ctrl.requirement_url if ctrl else "",
            },
            recommendations = llm_result.get("recommendations", []),
        )
