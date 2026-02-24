# CALM Architecture vs Codebase Validator

Validates a Java codebase against CALM architecture JSON files using GPT-4o.
Detects missing controls, overstated claims, and architectural mismatches —
**without sending raw source code to the LLM**.

---

## Project Structure

```
fineract_validator/
├── main.py                        ← CLI entry point
├── models.py                      ← Shared dataclasses
├── requirements.txt
├── .env.example
│
├── scanner/
│   └── java_scanner.py            ← Scans Java files, extracts metadata
│
├── calm_parser/
│   └── calm_parser.py             ← Parses CALM JSON files
│
├── comparator/
│   └── llm_comparator.py          ← Sends summaries to GPT-4o, classifies controls
│
├── reporter/
│   └── report_generator.py        ← Produces JSON + Markdown + gaps report
│
└── utils/
    ├── logger.py                  ← Centralised logging
    └── github_downloader.py       ← Clones GitHub repos to temp dir
```

---

## Setup

```bash
# 1. Clone this project
cd fineract_validator

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
# Edit .env and set OPENAI_API_KEY=sk-proj-...
```

---

## Usage

### Validate Apache Fineract from GitHub

```bash
python main.py \
  --source https://github.com/apache/fineract \
  --calm fineract-system.architecture.json fineract-platform-detailed.architecture.json \
  --output ./reports
```

### Validate a local codebase

```bash
python main.py \
  --source /path/to/fineract \
  --calm fineract-system.architecture.json \
  --output ./reports
```

### All CLI options

```
--source   / -s   Local path OR GitHub URL to the Java codebase         [required]
--calm     / -c   One or more CALM JSON file paths                        [required]
--output   / -o   Output directory for reports              (default: ./reports)
--model           OpenAI model to use                    (default: gpt-4o-mini)
--max-files       Max Java files to scan                       (default: 500)
--log-level       Logging verbosity: DEBUG/INFO/WARNING/ERROR  (default: INFO)
```

---

## Output Files

| File | Description |
|------|-------------|
| `reports/audit_report.json` | Full structured JSON with all validation results |
| `reports/audit_report.md`   | Human-readable Markdown with compliance matrix and remediation plan |
| `reports/gaps.json`         | Only non-compliant controls, sorted by risk severity |

### Example `gaps.json` entry

```json
{
  "control_id": "fineract-api-gateway/api-rate-limiting",
  "node_id": "fineract-api-gateway",
  "control_name": "API rate limiting using Resilience4j",
  "declared": true,
  "classification": "DECLARED_BUT_NOT_FOUND",
  "risk": "HIGH",
  "reasoning": "CALM declares Resilience4j RateLimiter but no RateLimiter classes or @RateLimiter annotations were found in the scan.",
  "recommendations": [
    "Add Resilience4j RateLimiter configuration to the API gateway layer.",
    "Annotate rate-limited endpoints with @RateLimiter."
  ],
  "evidence": {
    "calm_config": {
      "requests-per-minute": 1000,
      "framework": "Resilience4j RateLimiter",
      "strategy": "token-bucket",
      "scope": "per-tenant"
    }
  }
}
```

---

## How It Works

```
GitHub / Local Path
        │
        ▼
  JavaScanner                     (no code sent to LLM)
  ├── Regex extracts: packages, annotations, imports, class names
  ├── Detects: Spring Security, OAuth2, JWT, RBAC, Kafka,
  │            Resilience4j, CQRS, Batch, Audit logging ...
  └── Returns: CodeSummary (structured dict, ~2KB)
        │
        ▼
  CalmParser
  ├── Reads CALM JSON files
  ├── Extracts: nodes, controls, config, compliance references
  └── Returns: CalmSummary
        │
        ▼
  LLMComparator  ──── GPT-4o ────►  Classification per control
  ├── Chunks controls (8 per call)       IMPLEMENTED
  ├── Sends: CodeSummary + controls      PARTIALLY_IMPLEMENTED
  ├── temperature=0 (deterministic)      DECLARED_BUT_NOT_FOUND
  └── Parses JSON response               OVERSTATED
        │                                INFRASTRUCTURE_LEVEL
        ▼                                OPTIONAL
  ReportGenerator
  ├── audit_report.json
  ├── audit_report.md  (compliance matrix + remediation roadmap)
  └── gaps.json
```

---

## LLM Prompt Strategy

The LLM never sees raw source code. It receives:

- `code_summary` — detected patterns (booleans), top packages, key class names
- `calm_controls` — control ID, description, full config from CALM JSON

Controls are chunked into groups of 8 to stay within context limits.
`temperature=0` ensures deterministic, auditable output.
`response_format: json_object` enforces structured JSON responses.

---

## Extending the Tool

**Add a new framework detector:** Add entries to `SIGNATURES` in `scanner/java_scanner.py`.

**Support additional CALM schemas:** Update `calm_parser/calm_parser.py` to handle new CALM fields.

**Add a new report format (e.g., HTML, CSV):** Add a method to `reporter/report_generator.py`.

**Switch to Claude/Gemini:** Replace the `openai` client in `comparator/llm_comparator.py`.
