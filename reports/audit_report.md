# CALM Architecture vs Codebase — Validation Report
> Generated: 2026-02-24 09:40 UTC  
> Source: `https://github.com/apache/fineract`  
> CALM files: `fineract-system.architecture.json`, `fineract-platform-detailed.architecture.json`

## Executive Summary

Scanned **500 Java files** across **164 packages**.
Evaluated **20 CALM controls** declared across **22 nodes**.

| Metric | Value |
|--------|-------|
| Architecture type | Monolith |
| CQRS detected | Yes |
| Spring Security | Yes |
| Kafka / Messaging | No |
| Resilience4j | Yes |

## Risk Summary

| Classification | Count |
|----------------|-------|
| ✅ IMPLEMENTED | 9 |
| ⚠️  PARTIALLY_IMPLEMENTED | 0 |
| ❌ DECLARED_BUT_NOT_FOUND | 11 |
| 🔶 OVERSTATED | 0 |
| 🏗️  INFRASTRUCTURE_LEVEL | 0 |
| ℹ️  OPTIONAL | 0 |

| Risk Level | Count |
|------------|-------|
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 8 |

## Control Compliance Matrix

| Control | Node | Classification | Risk | Summary |
|---------|------|----------------|------|---------|
| `fineract-platform-core/rbac-authorization` | `fineract-platform-core` | ❌ DECLARED_BUT_NOT_FOUND | 🔴 CRITICAL | CALM claims RBAC is implemented, but no evidence of role-based access control found in the codebase. |
| `portfolio-module/rbac-authorization` | `portfolio-module` | ❌ DECLARED_BUT_NOT_FOUND | 🔴 CRITICAL | CALM claims RBAC for portfolio operations, but no evidence of role-based access control mechanisms is found in the codeb… |
| `user-administration-module/rbac-authorization` | `user-administration-module` | ❌ DECLARED_BUT_NOT_FOUND | 🔴 CRITICAL | CALM claims RBAC is implemented using Spring Security, but no evidence of role-based access control classes or configura… |
| `accounting-module/double-entry-accounting` | `accounting-module` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | The control for double-entry accounting integrity is declared, but no evidence of enforcement or validation rules is fou… |
| `batch-job-scheduler/circuit-breaker` | `batch-job-scheduler` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM declares a circuit breaker for batch operations using Resilience4j, but no circuit breaker classes or configuration… |
| `cob-module/circuit-breaker` | `cob-module` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM claims the use of Resilience4j for circuit breaking, but no circuit breaker classes or configurations found in the … |
| `fineract-api-gateway/mfa-authentication` | `fineract-api-gateway` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM declares MFA for API access, but no evidence of MFA implementation found in the codebase. |
| `fineract-api-gateway/api-rate-limiting` | `fineract-api-gateway` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM claims API rate limiting with Resilience4j, but no RateLimiter classes or configurations found in the codebase. |
| `portfolio-module/audit-logging` | `portfolio-module` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM states that immutable audit logs are maintained for portfolio operations, but no relevant logging classes or config… |
| `user-administration-module/password-policy` | `user-administration-module` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | The password policy control is declared, but no evidence of password policy enforcement is found in the codebase. |
| `user-administration-module/session-management` | `user-administration-module` | ❌ DECLARED_BUT_NOT_FOUND | 🟠 HIGH | CALM declares secure session management but no session management classes or configurations found in the codebase. |
| `fineract-api-gateway/audit-logging` | `fineract-api-gateway` | ✅ IMPLEMENTED | 🟡 MEDIUM | Audit logging is implemented as evidenced by the presence of audit classes in the codebase. |
| `fineract-platform-core/input-validation` | `fineract-platform-core` | ✅ IMPLEMENTED | 🟡 MEDIUM | Input validation is implemented as indicated by the presence of validation classes and annotations. |
| `fineract-platform-core/audit-logging` | `fineract-platform-core` | ✅ IMPLEMENTED | 🟡 MEDIUM | Comprehensive audit logging is implemented as evidenced by the presence of relevant classes in the codebase. |
| `accounting-module/audit-logging` | `accounting-module` | ✅ IMPLEMENTED | 🟢 LOW | Audit logging for accounting transactions is implemented with classes that handle logging of journal entries and posting… |
| `batch-job-scheduler/audit-logging` | `batch-job-scheduler` | ✅ IMPLEMENTED | 🟢 LOW | Audit logging is implemented in the codebase with classes that handle logging for batch job executions. |
| `cob-module/transaction-integrity` | `cob-module` | ✅ IMPLEMENTED | 🟢 LOW | ACID transaction integrity is supported as indicated by the presence of transaction management in the codebase. |
| `fineract-api-gateway/tls-encryption` | `fineract-api-gateway` | ✅ IMPLEMENTED | 🟢 LOW | TLS configuration is detected, indicating that TLS encryption is implemented for API communications. |
| `fineract-platform-core/transaction-integrity` | `fineract-platform-core` | ✅ IMPLEMENTED | 🟢 LOW | ACID transaction guarantees are implemented as indicated by transaction management in the codebase. |
| `portfolio-module/input-validation` | `portfolio-module` | ✅ IMPLEMENTED | 🟢 LOW | Input validation is present in the codebase, with mechanisms to prevent SQL injection and XSS. |

## Detailed Gap Findings

### 🔴 `fineract-platform-core/rbac-authorization`
**Node:** `fineract-platform-core`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** CRITICAL  

**Reasoning:** CALM claims RBAC is implemented, but no evidence of role-based access control found in the codebase.

**Recommendations:**
- Implement role-based access control using Spring Security.
- Define roles and permissions for different user types.

<details><summary>CALM Config</summary>

```json
{
  "authorization-framework": "Spring Security",
  "granularity": "fine-grained",
  "default-policy": "deny-all",
  "least-privilege": true,
  "segregation-of-duties": true,
  "role-hierarchy": true,
  "compliance-framework": "ISO27001"
}
```

</details>

### 🔴 `portfolio-module/rbac-authorization`
**Node:** `portfolio-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** CRITICAL  

**Reasoning:** CALM claims RBAC for portfolio operations, but no evidence of role-based access control mechanisms is found in the codebase.

**Recommendations:**
- Implement RBAC using Spring Security for portfolio operations.
- Define roles and permissions according to the least privilege principle.

<details><summary>CALM Config</summary>

```json
{
  "authorization-framework": "Spring Security",
  "granularity": "fine-grained",
  "default-policy": "deny-all",
  "least-privilege": true,
  "segregation-of-duties": true,
  "role-hierarchy": true,
  "compliance-framework": "NIST-800-53"
}
```

</details>

### 🔴 `user-administration-module/rbac-authorization`
**Node:** `user-administration-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** CRITICAL  

**Reasoning:** CALM claims RBAC is implemented using Spring Security, but no evidence of role-based access control classes or configurations found.

**Recommendations:**
- Implement role-based access control using Spring Security.
- Define user roles and permissions in the application.

<details><summary>CALM Config</summary>

```json
{
  "authorization-framework": "Spring Security",
  "granularity": "fine-grained",
  "default-policy": "deny-all",
  "least-privilege": true,
  "segregation-of-duties": true,
  "role-hierarchy": true,
  "compliance-framework": "ISO27001"
}
```

</details>

### 🟠 `accounting-module/double-entry-accounting`
**Node:** `accounting-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** The control for double-entry accounting integrity is declared, but no evidence of enforcement or validation rules is found in the codebase.

**Recommendations:**
- Implement double-entry accounting checks to ensure debits equal credits.
- Establish reconciliation processes as per GAAP.

<details><summary>CALM Config</summary>

```json
{
  "validation-rule": "debits-equal-credits",
  "enforcement-level": "pre-commit",
  "reconciliation-frequency": "daily",
  "compliance-framework": "GAAP"
}
```

</details>

### 🟠 `batch-job-scheduler/circuit-breaker`
**Node:** `batch-job-scheduler`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM declares a circuit breaker for batch operations using Resilience4j, but no circuit breaker classes or configurations are found in the codebase.

**Recommendations:**
- Implement Resilience4j circuit breaker for batch job operations.
- Configure failure thresholds and timeouts as per CALM specifications.

<details><summary>CALM Config</summary>

```json
{
  "framework": "Resilience4j",
  "failure-threshold": 5,
  "timeout": "30 seconds",
  "reset-timeout": "1 minute",
  "half-open-max-calls": 3
}
```

</details>

### 🟠 `cob-module/circuit-breaker`
**Node:** `cob-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM claims the use of Resilience4j for circuit breaking, but no circuit breaker classes or configurations found in the codebase.

**Recommendations:**
- Implement circuit breaker functionality using Resilience4j in the COB module.
- Configure failure thresholds and timeouts as specified.

<details><summary>CALM Config</summary>

```json
{
  "framework": "Resilience4j",
  "failure-threshold": 3,
  "timeout": "5 minutes",
  "reset-timeout": "10 minutes",
  "half-open-max-calls": 1
}
```

</details>

### 🟠 `fineract-api-gateway/mfa-authentication`
**Node:** `fineract-api-gateway`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM declares MFA for API access, but no evidence of MFA implementation found in the codebase.

**Recommendations:**
- Implement multi-factor authentication using Spring Security.
- Integrate OTP generation and validation mechanisms.

<details><summary>CALM Config</summary>

```json
{
  "mfa-factors": [
    "password",
    "OTP"
  ],
  "mfa-enforcement": "role-based",
  "token-expiry": "1 hour access token, 24 hour refresh token"
}
```

</details>

### 🟠 `fineract-api-gateway/api-rate-limiting`
**Node:** `fineract-api-gateway`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM claims API rate limiting with Resilience4j, but no RateLimiter classes or configurations found in the codebase.

**Recommendations:**
- Add Resilience4j RateLimiter configuration to the API gateway layer.
- Annotate rate-limited endpoints with @RateLimiter.

<details><summary>CALM Config</summary>

```json
{
  "requests-per-minute": 1000,
  "framework": "Resilience4j RateLimiter",
  "strategy": "token-bucket",
  "scope": "per-tenant"
}
```

</details>

### 🟠 `portfolio-module/audit-logging`
**Node:** `portfolio-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM states that immutable audit logs are maintained for portfolio operations, but no relevant logging classes or configurations are found.

**Recommendations:**
- Implement immutable audit logging for portfolio operations.
- Ensure compliance with SOX by logging specified events.

<details><summary>CALM Config</summary>

```json
{
  "log-level": "comprehensive",
  "retention-period": "7 years",
  "immutability": "append-only",
  "storage-location": "m_portfolio_command_source",
  "logged-events": [
    "client-create",
    "loan-create",
    "savings-create"
  ],
  "compliance-framework": "SOX"
}
```

</details>

### 🟠 `user-administration-module/password-policy`
**Node:** `user-administration-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** The password policy control is declared, but no evidence of password policy enforcement is found in the codebase.

**Recommendations:**
- Implement strong password policies as per NIST-800-63B.
- Ensure password complexity and expiry requirements are enforced.

<details><summary>CALM Config</summary>

```json
{
  "algorithm": "bcrypt",
  "min-length": 12,
  "complexity-requirements": {
    "uppercase": true,
    "lowercase": true,
    "numbers": true,
    "special-chars": true
  },
  "expiry-days": 90,
  "history-count": 5,
  "compliance-framework": "NIST-800-63B"
}
```

</details>

### 🟠 `user-administration-module/session-management`
**Node:** `user-administration-module`  
**Classification:** ❌ DECLARED_BUT_NOT_FOUND  
**Risk:** HIGH  

**Reasoning:** CALM declares secure session management but no session management classes or configurations found in the codebase.

**Recommendations:**
- Implement session management features in the user administration module.
- Ensure session timeout, secure cookies, and session fixation protection are configured.

<details><summary>CALM Config</summary>

```json
{
  "timeout-minutes": 30,
  "max-sessions-per-user": 1,
  "session-fixation-protection": true,
  "secure-cookie": true,
  "http-only-cookie": true,
  "same-site-policy": "Strict"
}
```

</details>

## Remediation Roadmap

Ordered by risk. Address Critical and High items first.

1. **[CRITICAL]** `fineract-platform-core/rbac-authorization` — Implement role-based access control using Spring Security.
2. **[CRITICAL]** `portfolio-module/rbac-authorization` — Implement RBAC using Spring Security for portfolio operations.
3. **[CRITICAL]** `user-administration-module/rbac-authorization` — Implement role-based access control using Spring Security.
4. **[HIGH]** `accounting-module/double-entry-accounting` — Implement double-entry accounting checks to ensure debits equal credits.
5. **[HIGH]** `batch-job-scheduler/circuit-breaker` — Implement Resilience4j circuit breaker for batch job operations.
6. **[HIGH]** `cob-module/circuit-breaker` — Implement circuit breaker functionality using Resilience4j in the COB module.
7. **[HIGH]** `fineract-api-gateway/mfa-authentication` — Implement multi-factor authentication using Spring Security.
8. **[HIGH]** `fineract-api-gateway/api-rate-limiting` — Add Resilience4j RateLimiter configuration to the API gateway layer.
9. **[HIGH]** `portfolio-module/audit-logging` — Implement immutable audit logging for portfolio operations.
10. **[HIGH]** `user-administration-module/password-policy` — Implement strong password policies as per NIST-800-63B.
11. **[HIGH]** `user-administration-module/session-management` — Implement session management features in the user administration module.
