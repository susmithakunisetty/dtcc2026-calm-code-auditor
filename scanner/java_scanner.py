"""
scanner/java_scanner.py
=======================
Recursively scans a Java codebase and extracts structural metadata
without sending source code to the LLM.

Detection strategy:
  - Regex-based extraction (annotations, imports, package, class declarations)
  - Pattern matching against known framework signatures
  - Aggregation into a CodeSummary dataclass
"""

from __future__ import annotations

import logging
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from models import CodeSummary, JavaFileMetadata
from utils.github_downloader import resolve_source

log = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────────

RE_PACKAGE    = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
RE_CLASS      = re.compile(r"(?:class|interface|enum|record)\s+(\w+)")
RE_ANNOTATION = re.compile(r"@([\w.]+)(?:\(.*?\))?")
RE_IMPORT     = re.compile(r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;", re.MULTILINE)
RE_EXTENDS    = re.compile(r"\bextends\s+([\w<>, ]+?)(?:\s+implements|\s*\{)")
RE_IMPLEMENTS = re.compile(r"\bimplements\s+([\w<>, ]+?)(?:\s*\{)")

# ── Framework / pattern signatures ────────────────────────────────────────

SIGNATURES: dict[str, list[str]] = {
    "spring_boot":          ["org.springframework.boot", "SpringApplication", "@SpringBootApplication"],
    "spring_security":      ["org.springframework.security", "WebSecurityConfigurerAdapter",
                             "SecurityFilterChain", "@EnableWebSecurity", "HttpSecurity"],
    "oauth2":               ["oauth2", "OAuth2", "OAuthClient", "TokenGranter",
                             "spring.security.oauth2"],
    "jwt":                  ["jwt", "JWT", "JwtDecoder", "JwtEncoder", "io.jsonwebtoken",
                             "com.auth0.jwt"],
    "mfa":                  ["MFA", "Mfa", "MultiFactorAuth", "OtpService", "TotpService",
                             "GoogleAuthenticator"],
    "rbac":                 ["@PreAuthorize", "@Secured", "@RolesAllowed",
                             "GrantedAuthority", "SimpleGrantedAuthority", "hasRole",
                             "hasAuthority", "RoleHierarchy"],
    "kafka":                ["org.apache.kafka", "KafkaTemplate", "@KafkaListener",
                             "KafkaProducer", "KafkaConsumer", "spring.kafka"],
    "jpa":                  ["javax.persistence", "jakarta.persistence", "@Entity",
                             "@Repository", "JpaRepository", "EntityManager"],
    "batch":                ["spring.batch", "@EnableBatchProcessing", "JobLauncher",
                             "StepBuilderFactory", "ItemReader", "ItemWriter", "ItemProcessor"],
    "resilience4j":         ["io.github.resilience4j", "Resilience4j", "@CircuitBreaker",
                             "@RateLimiter", "@Retry", "@Bulkhead", "CircuitBreakerRegistry"],
    "rate_limiter":         ["RateLimiter", "@RateLimiter", "RateLimiterRegistry",
                             "RateLimitInterceptor"],
    "circuit_breaker":      ["@CircuitBreaker", "CircuitBreaker", "CircuitBreakerRegistry",
                             "CircuitBreakerConfig"],
    "audit_logging":        ["AuditLog", "CommandSource", "m_portfolio_command_source",
                             "@Audited", "AuditTrail", "AuditService", "CommandProcessingResult",
                             "AuditReadPlatformService"],
    "tls_config":           ["SSLContext", "TrustManagerFactory", "KeyManagerFactory",
                             "SslBundle", "server.ssl", "https", "TlsProperties"],
    "input_validation":     ["@Valid", "@Validated", "@NotNull", "@Size", "@Pattern",
                             "@Email", "@NotBlank", "ConstraintValidator",
                             "jakarta.validation", "javax.validation"],
    "transaction_mgmt":     ["@Transactional", "PlatformTransactionManager",
                             "TransactionTemplate", "@EnableTransactionManagement"],
    "cqrs":                 ["CommandHandler", "QueryHandler", "CommandBus", "QueryBus",
                             "CommandProcessing", "CommandSource",
                             "CommandProcessingResultBuilder"],
    "monolith_indicator":   ["org.apache.fineract", "fineract-provider"],
    "microservice_indicator":["spring.cloud", "EurekaClient", "FeignClient",
                              "@EnableDiscoveryClient", "Ribbon", "Zuul"],
}

# Maps signature key → CodeSummary boolean field name
BOOL_FIELD_MAP = {
    "spring_boot":           "has_spring_boot",
    "spring_security":       "has_spring_security",
    "oauth2":                "has_oauth2",
    "jwt":                   "has_jwt",
    "mfa":                   "has_mfa",
    "rbac":                  "has_rbac",
    "kafka":                 "has_kafka",
    "jpa":                   "has_jpa",
    "batch":                 "has_batch",
    "resilience4j":          "has_resilience4j",
    "rate_limiter":          "has_rate_limiter",
    "circuit_breaker":       "has_circuit_breaker",
    "audit_logging":         "has_audit_logging",
    "tls_config":            "has_tls_config",
    "input_validation":      "has_input_validation",
    "transaction_mgmt":      "has_transaction_management",
}

# Class-level collectors — pattern to attribute on CodeSummary
CLASS_COLLECTORS: dict[str, tuple[str, list[str]]] = {
    # attribute_name: (summary_field, trigger_annotations_or_imports)
    "rest_controllers":    ["@RestController", "@Controller"],
    "command_handlers":    ["CommandHandler", "CommandProcessing", "CommandSource"],
    "query_handlers":      ["QueryHandler", "ReadPlatformService"],
    "security_classes":    ["@EnableWebSecurity", "WebSecurityConfigurerAdapter",
                            "SecurityFilterChain", "AuthenticationProvider"],
    "audit_classes":       ["AuditLog", "AuditTrail", "CommandSource", "@Audited",
                            "AuditService"],
    "batch_classes":       ["@EnableBatchProcessing", "ItemReader", "ItemWriter",
                            "JobLauncher", "Step"],
    "kafka_classes":       ["@KafkaListener", "KafkaTemplate", "KafkaProducer"],
    "resilience_classes":  ["@CircuitBreaker", "@RateLimiter", "CircuitBreakerRegistry"],
    "validation_classes":  ["@Valid", "@Validated", "ConstraintValidator"],
}

MAX_CLASSES_PER_TYPE = 30   # cap to keep prompts lean


class JavaScanner:
    """
    Scans a local or remote Java codebase and returns a CodeSummary.
    """

    def __init__(self, source: str, max_files: int = 500) -> None:
        self.source = source
        self.max_files = max_files
        self._tmp_dir: Path | None = None

    # ── Public API ────────────────────────────────────────────────

    def scan(self) -> CodeSummary:
        local_path = resolve_source(self.source)
        java_files = self._collect_java_files(local_path)

        log.info(f"Found {len(java_files)} Java files (scanning up to {self.max_files}).")
        java_files = java_files[: self.max_files]

        all_metadata: list[JavaFileMetadata] = []
        for jf in java_files:
            try:
                meta = self._parse_file(jf)
                all_metadata.append(meta)
            except Exception as exc:
                log.debug(f"Skipping {jf}: {exc}")

        return self._aggregate(local_path, all_metadata)

    # ── Internal helpers ──────────────────────────────────────────

    def _collect_java_files(self, root: Path) -> list[Path]:
        return [
            p for p in sorted(root.rglob("*.java"))
            if ".git" not in p.parts
        ]

    def _parse_file(self, path: Path) -> JavaFileMetadata:
        text = path.read_text(encoding="utf-8", errors="replace")

        package = (RE_PACKAGE.search(text) or type("m", (), {"group": lambda s, i: ""})()).group(1) or ""
        classes = RE_CLASS.findall(text)
        class_name = classes[0] if classes else path.stem
        annotations = RE_ANNOTATION.findall(text)
        imports = RE_IMPORT.findall(text)
        extends = RE_EXTENDS.findall(text)
        implements = RE_IMPLEMENTS.findall(text)

        return JavaFileMetadata(
            path=str(path),
            package=package,
            class_name=class_name,
            annotations=annotations,
            imports=imports,
            implemented_interfaces=[i.strip() for item in implements for i in item.split(",")],
            extended_classes=[e.strip() for item in extends for e in item.split(",")],
            is_test="test" in str(path).lower(),
        )

    def _aggregate(self, root: Path, metadata: list[JavaFileMetadata]) -> CodeSummary:
        summary = CodeSummary(source=self.source)
        summary.total_files = len(metadata)

        # Packages
        summary.packages = sorted(set(m.package for m in metadata if m.package))

        # Annotation & import frequency counters
        ann_counter: Counter = Counter()
        imp_counter: Counter = Counter()
        for m in metadata:
            ann_counter.update(m.annotations)
            imp_counter.update(m.imports)
        summary.all_annotations = dict(ann_counter.most_common(100))
        summary.all_imports     = dict(imp_counter.most_common(150))

        # Combine all text tokens for signature matching
        all_tokens = (
            list(ann_counter.keys())
            + list(imp_counter.keys())
            + summary.packages
        )
        all_tokens_str = " ".join(all_tokens)

        # Detect boolean pattern flags
        for sig_key, sig_tokens in SIGNATURES.items():
            matched = any(tok in all_tokens_str for tok in sig_tokens)
            field = BOOL_FIELD_MAP.get(sig_key)
            if field:
                setattr(summary, field, matched)

        # Monolith vs microservice
        summary.is_monolith      = any(tok in all_tokens_str for tok in SIGNATURES["monolith_indicator"])
        summary.is_microservice  = any(tok in all_tokens_str for tok in SIGNATURES["microservice_indicator"])
        if not summary.is_microservice:
            summary.is_monolith = True   # default assumption for single-repo scans

        # CQRS
        summary.has_cqrs = any(tok in all_tokens_str for tok in SIGNATURES["cqrs"])

        # Class-level collectors
        def collect_classes(trigger_tokens: list[str]) -> list[str]:
            results = []
            for m in metadata:
                combined = " ".join(m.annotations + m.imports + [m.class_name] +
                                    m.implemented_interfaces + m.extended_classes)
                if any(tok in combined for tok in trigger_tokens):
                    results.append(f"{m.package}.{m.class_name}")
            return results[:MAX_CLASSES_PER_TYPE]

        summary.rest_controllers  = collect_classes(CLASS_COLLECTORS["rest_controllers"])
        summary.command_handlers  = collect_classes(CLASS_COLLECTORS["command_handlers"])
        summary.query_handlers    = collect_classes(CLASS_COLLECTORS["query_handlers"])
        summary.security_classes  = collect_classes(CLASS_COLLECTORS["security_classes"])
        summary.audit_classes     = collect_classes(CLASS_COLLECTORS["audit_classes"])
        summary.batch_classes     = collect_classes(CLASS_COLLECTORS["batch_classes"])
        summary.kafka_classes     = collect_classes(CLASS_COLLECTORS["kafka_classes"])
        summary.resilience_classes = collect_classes(CLASS_COLLECTORS["resilience_classes"])
        summary.validation_classes = collect_classes(CLASS_COLLECTORS["validation_classes"])

        return summary
