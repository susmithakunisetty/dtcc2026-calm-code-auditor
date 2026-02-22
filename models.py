"""
models.py — Shared dataclasses for the entire validation pipeline.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ── Code scanning models ──────────────────────────────────────────────────

@dataclass
class JavaFileMetadata:
    """Metadata extracted from a single Java source file."""
    path: str
    package: str
    class_name: str
    annotations: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    implemented_interfaces: list[str] = field(default_factory=list)
    extended_classes: list[str] = field(default_factory=list)
    is_test: bool = False


@dataclass
class CodeSummary:
    """Aggregated summary of the entire scanned codebase."""
    source: str
    total_files: int = 0
    packages: list[str] = field(default_factory=list)
    all_annotations: dict[str, int] = field(default_factory=dict)   # annotation → count
    all_imports: dict[str, int] = field(default_factory=dict)        # import → count

    # Detected patterns (True/False)
    is_monolith: bool = False
    is_microservice: bool = False
    has_cqrs: bool = False
    has_spring_security: bool = False
    has_spring_boot: bool = False
    has_oauth2: bool = False
    has_jwt: bool = False
    has_mfa: bool = False
    has_rbac: bool = False
    has_kafka: bool = False
    has_jpa: bool = False
    has_batch: bool = False
    has_resilience4j: bool = False
    has_rate_limiter: bool = False
    has_circuit_breaker: bool = False
    has_audit_logging: bool = False
    has_tls_config: bool = False
    has_input_validation: bool = False
    has_transaction_management: bool = False

    # Key class lists (capped for prompt efficiency)
    security_classes: list[str] = field(default_factory=list)
    audit_classes: list[str] = field(default_factory=list)
    command_handlers: list[str] = field(default_factory=list)
    query_handlers: list[str] = field(default_factory=list)
    rest_controllers: list[str] = field(default_factory=list)
    batch_classes: list[str] = field(default_factory=list)
    kafka_classes: list[str] = field(default_factory=list)
    resilience_classes: list[str] = field(default_factory=list)
    validation_classes: list[str] = field(default_factory=list)


# ── CALM parsing models ───────────────────────────────────────────────────

@dataclass
class CalmControl:
    """A single control extracted from a CALM JSON node."""
    control_id: str
    node_id: str
    node_name: str
    node_type: str
    description: str
    config: dict[str, Any] = field(default_factory=dict)
    requirement_url: str = ""


@dataclass
class CalmRelationship:
    source: str
    target: str
    relationship_type: str
    protocol: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class CalmSummary:
    """Everything extracted from one or more CALM JSON files."""
    source_files: list[str] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    controls: list[CalmControl] = field(default_factory=list)
    relationships: list[CalmRelationship] = field(default_factory=list)
    declared_frameworks: list[str] = field(default_factory=list)
    declared_compliance: list[str] = field(default_factory=list)


# ── Validation result models ──────────────────────────────────────────────

CLASSIFICATION_VALUES = [
    "IMPLEMENTED",
    "PARTIALLY_IMPLEMENTED",
    "DECLARED_BUT_NOT_FOUND",
    "OVERSTATED",
    "INFRASTRUCTURE_LEVEL",
    "OPTIONAL",
]

RISK_VALUES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class ValidationResult:
    """LLM-produced validation result for a single CALM control."""
    control_id: str
    node_id: str
    control_name: str
    declared: bool
    classification: str                    # one of CLASSIFICATION_VALUES
    risk: str                              # one of RISK_VALUES
    reasoning: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
