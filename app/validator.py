"""
CALM Architecture Validator
Reads CALM architecture JSON files and runtime .log file
Outputs:
 - validation_report_<timestamp>.txt
 - gaps.json
"""

import os
import json
import re
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
print  (f"Base directory: {BASE_DIR}")  # Debugging statement to verify path resolution
ARCHITECTURE_DIR = BASE_DIR / "architecture"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "logreports"

SYSTEM_ARCH_FILE = ARCHITECTURE_DIR / "fineract-system.architecture.json"
DETAILED_ARCH_FILE = ARCHITECTURE_DIR / "fineract-platform-detailed.architecture.json"
LOG_FILE = LOGS_DIR / "runtime.log"

MODEL = "gpt-4o-mini"


# ---------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------

def load_json(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_log_file(log_path: Path):
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    parsed_logs = []

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            log_entry = {}
            parts = line.split()

            for part in parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    log_entry[key] = value

            parsed_logs.append(log_entry)

    return parsed_logs


def save_text_report(report_content: str):
    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_file = REPORTS_DIR / f"validation_report_{timestamp}.txt"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_content)

    return report_file


def save_gaps_json(gaps_data: dict):
    gaps_file = REPORTS_DIR / "gaps.json"
    with open(gaps_file, "w", encoding="utf-8") as f:
        json.dump(gaps_data, f, indent=2)
    return gaps_file


def extract_json_block(text: str):
    """
    Extract JSON block between markers:
    ---GAPS_JSON_START---
    ---GAPS_JSON_END---
    """
    pattern = r"---GAPS_JSON_START---(.*?)---GAPS_JSON_END---"
    match = re.search(pattern, text, re.DOTALL)

    if not match:
        return None

    json_text = match.group(1).strip()

    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        return None


def build_prompt(system_arch, detailed_arch, logs):
    return f"""
You are an enterprise architecture compliance auditor specialized in FINOS CALM models.

Perform these validations:

1. Validate that all log services exist in architecture nodes.
2. Validate relationship consistency.
3. Validate control coverage (RBAC, MFA, TLS, audit logging, transaction integrity).
4. Detect anomalies.
5. Detect missing control evidence.

Provide:

A human-readable report.

Then provide a structured JSON output of all identified gaps in the following format:

---GAPS_JSON_START---
{{
  "architecture_issues": [],
  "log_inconsistencies": [],
  "security_control_gaps": [],
  "operational_risks": [],
  "recommendations": [],
  "compliance_score": 0
}}
---GAPS_JSON_END---

System Architecture:
{json.dumps(system_arch, indent=2)}

Detailed Architecture:
{json.dumps(detailed_arch, indent=2)}

Parsed Runtime Logs:
{json.dumps(logs, indent=2)}
"""


# ---------------------------------------------------------
# Core Validator
# ---------------------------------------------------------

def validate_architecture():
    print("Loading architecture files...")
    system_arch = load_json(SYSTEM_ARCH_FILE)
    detailed_arch = load_json(DETAILED_ARCH_FILE)

    print("Parsing runtime log file...")
    logs = parse_log_file(LOG_FILE)

    print("Calling GPT-4o Mini for validation...")
    client = OpenAI()

    prompt = build_prompt(system_arch, detailed_arch, logs)

    response = client.chat.completions.create(
        model=MODEL,
        temperature=0.2,
        messages=[
            {"role": "system", "content": "You are a senior enterprise architecture auditor."},
            {"role": "user", "content": prompt}
        ]
    )

    report_text = response.choices[0].message.content

    print("Saving text report...")
    report_path = save_text_report(report_text)

    print("Extracting structured gaps...")
    gaps_data = extract_json_block(report_text)

    if gaps_data:
        gaps_path = save_gaps_json(gaps_data)
        print(f" Gaps JSON saved at: {gaps_path}")
    else:
        print(" Could not extract structured JSON gaps.")

    print("\n Validation Complete")
    print(f"Text report saved at: {report_path}")

    return report_text


# ---------------------------------------------------------
# Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":
    load_dotenv()

    if not os.getenv("OPENAI_API_KEY"):
        raise EnvironmentError("OPENAI_API_KEY not set in environment")

    try:
        validate_architecture()
    except Exception as e:
        print(f" Validation failed: {str(e)}")