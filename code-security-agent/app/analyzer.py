import os
import re
import json
import uuid
import logging
from datetime import datetime, timezone
from openai import OpenAI
from .models import SecurityReport, SecurityIssue, Severity

logger = logging.getLogger(__name__)

# ── LM Studio / MLX configuration ──────────────────────────────────────────
# LM Studio exposes an OpenAI-compatible REST API.
# Set these env vars in your Kubernetes manifest or ConfigMap.
LLAMA_BASE_URL = os.getenv("LLAMA_BASE_URL", "http://lm-studio-service:1234/v1")
LLAMA_API_KEY  = os.getenv("LLAMA_API_KEY", "lm-studio")   # LM Studio ignores this value
LLAMA_MODEL    = os.getenv("LLAMA_MODEL", "llama-4")        # Match the name shown in LM Studio
MAX_TOKENS     = int(os.getenv("MAX_TOKENS", "8192"))
TEMPERATURE    = float(os.getenv("TEMPERATURE", "0.1"))

client = OpenAI(base_url=LLAMA_BASE_URL, api_key=LLAMA_API_KEY)

# ── Prompts ─────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert application security engineer specializing in secure code review.
Your job is to find real security vulnerabilities in source code — not style issues or performance suggestions.

You MUST respond with a single valid JSON object and NOTHING else (no markdown, no code fences, no explanation).

Required JSON schema:
{
  "issues": [
    {
      "id": "ISSUE-001",
      "title": "Short vulnerability title",
      "severity": "critical|high|medium|low|info",
      "file": "filename.ext",
      "line_start": 12,
      "line_end": 15,
      "description": "What the vulnerability is and why it is dangerous",
      "vulnerable_code": "exact snippet from the code",
      "fix_suggestion": "Concrete fix with corrected code example",
      "cwe_id": "CWE-89"
    }
  ],
  "summary": "1-3 sentence overall security assessment"
}

Security categories to check (non-exhaustive):
- Injection: SQL, command, LDAP, XPath, template, SSTI
- Broken authentication: weak passwords, insecure session tokens
- Sensitive data exposure: hardcoded secrets, API keys, tokens, passwords
- Cryptographic failures: weak algorithms, insecure random, missing TLS
- Broken access control: missing auth checks, IDOR, path traversal
- Security misconfiguration: debug mode, verbose errors, open CORS
- XSS, CSRF, clickjacking
- Insecure deserialization
- SSRF
- Race conditions / TOCTOU
- Memory safety: buffer overflows, use-after-free (C/C++ code)
- Prototype pollution (JavaScript)
- Dependency confusion / supply chain risks
- Logging of sensitive data
- Insufficient input validation

If no issues are found, return {"issues": [], "summary": "No security issues found."}
"""


def _build_user_message(files: dict[str, str]) -> str:
    parts = ["Analyze the following source files for security vulnerabilities:\n"]
    for filename, content in files.items():
        parts.append(f"=== FILE: {filename} ===\n{content}\n")
    return "\n".join(parts)


def _extract_json(text: str) -> dict:
    """
    Try to extract a JSON object from the LLM response.
    Some MLX models wrap output in markdown code fences even when asked not to.
    """
    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown code fences  (```json ... ``` or ``` ... ```)
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Grab the first { ... } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from LLM response. Raw output:\n{text[:500]}")


def _count_by_severity(issues: list[SecurityIssue]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for issue in issues:
        counts[issue.severity.value] += 1
    return counts


def analyze_code(files: dict[str, str]) -> SecurityReport:
    """
    Send code files to Llama 4 via LM Studio and return a structured SecurityReport.
    """
    scan_id   = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    user_msg  = _build_user_message(files)

    logger.info(f"[{scan_id}] Sending {len(files)} file(s) to {LLAMA_BASE_URL} model={LLAMA_MODEL}")

    response = client.chat.completions.create(
        model=LLAMA_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
    )

    raw = response.choices[0].message.content
    logger.debug(f"[{scan_id}] Raw LLM response (first 200 chars): {raw[:200]}")

    parsed = _extract_json(raw)

    issues = []
    for i, item in enumerate(parsed.get("issues", []), start=1):
        # Normalise id if the model forgot
        if "id" not in item or not item["id"]:
            item["id"] = f"ISSUE-{i:03d}"
        # Normalise severity casing
        item["severity"] = item.get("severity", "info").lower()
        issues.append(SecurityIssue(**item))

    counts = _count_by_severity(issues)

    report = SecurityReport(
        scan_id=scan_id,
        timestamp=timestamp,
        files_analyzed=list(files.keys()),
        total_issues=len(issues),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        info_count=counts["info"],
        issues=issues,
        summary=parsed.get("summary", "Analysis complete."),
    )

    logger.info(
        f"[{scan_id}] Done — {len(issues)} issues "
        f"(critical={counts['critical']}, high={counts['high']}, "
        f"medium={counts['medium']}, low={counts['low']})"
    )
    return report
