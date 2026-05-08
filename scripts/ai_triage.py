"""
SecureFlow AI — AI Triage Engine
Reads all scanner JSON outputs, calls Claude or Gemini API,
produces a prioritized findings report and markdown PR comment.
"""

import importlib
import json
import os
import sys

# ── Config ────────────────────────────────────────────────────────────────
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")   # 'claude' or 'gemini'
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")
MAX_FINDINGS_PER_TOOL = 20   # token budget control


# ── Load scanner outputs ──────────────────────────────────────────────────
def load_json_safe(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def load_all_results():
    results = {}

    # Semgrep (SAST)
    data = load_json_safe("sast-results/semgrep.json")
    if data and "results" in data:
        results["sast"] = data["results"][:MAX_FINDINGS_PER_TOOL]

    # Trivy filesystem (SCA)
    data = load_json_safe("sca-results/trivy-fs.json")
    if data:
        vulns = []
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                if v.get("Severity") in ("CRITICAL", "HIGH"):
                    vulns.append({
                        "id": v.get("VulnerabilityID"),
                        "severity": v.get("Severity"),
                        "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "description": (v.get("Description") or "")[:300],
                    })
        results["sca"] = vulns[:MAX_FINDINGS_PER_TOOL]

    # Gitleaks (secrets)
    data = load_json_safe("secrets-results/gitleaks.json")
    if data and isinstance(data, list):
        results["secrets"] = [
            {"rule": s.get("RuleID"), "file": s.get("File"),
             "line": s.get("StartLine"), "match": "***REDACTED***"}
            for s in data[:10]
        ]

    # Hadolint
    data = load_json_safe("container-iac-results/hadolint.json")
    if data and isinstance(data, list):
        results["dockerfile"] = [
            {"code": h.get("code"), "message": h.get("message"),
             "severity": h.get("level")}
            for h in data if h.get("level") in ("error", "warning")
        ][:10]

    # Checkov
    data = load_json_safe("container-iac-results/checkov.json")
    if data:
        failed = data.get("results", {}).get("failed_checks", [])
        results["iac"] = [
            {"id": c.get("check_id"),
             "name": (c.get("check") or {}).get("name", ""),
             "file": c.get("repo_file_path")}
            for c in failed[:MAX_FINDINGS_PER_TOOL]
        ]

    return results


# ── Build prompt ──────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a senior application security engineer reviewing 
automated CI/CD scan results. Your job is to deduplicate findings, eliminate 
false positives, prioritize by real-world exploitability, and suggest concrete 
remediation. Return ONLY valid JSON — no markdown, no preamble."""

def build_user_prompt(results):
    return f"""Analyze these security scan results and return a JSON object.

=== SCAN RESULTS ===
{json.dumps(results, indent=2)}

=== REQUIRED OUTPUT FORMAT ===
Return this exact JSON (no other text):
{{
  "summary": {{
    "critical": <integer>,
    "high": <integer>,
    "medium": <integer>,
    "total_raw": <integer>,
    "false_positives": <integer>,
    "actionable": <integer>
  }},
  "findings": [
    {{
      "id": "<short unique id>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "tool": "<source scanner>",
      "title": "<30 words max>",
      "description": "<what the risk is and why it matters, 2-3 sentences>",
      "false_positive": <true|false>,
      "false_positive_reason": "<explanation if false positive, else null>",
      "remediation": "<specific fix — include a code snippet or command if applicable>",
      "priority": <integer 1-10, 10 = fix immediately>
    }}
  ],
  "gate_recommendation": "PASS|FAIL",
  "gate_reason": "<one sentence explaining the recommendation>"
}}

=== RULES ===
1. Deduplicate findings that appear across multiple tools (same CVE, same issue)
2. Mark findings in test/, mock/, or __tests__/ paths as false positives
3. Prioritize by: severity × exploitability × fix availability
4. Max 15 findings total, sorted by priority descending
5. Any hardcoded credential is always CRITICAL priority 10
6. Any CRITICAL CVE with a known fix is priority 9+
"""


# ── Call Claude API ───────────────────────────────────────────────────────
def call_claude(prompt):
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


# ── Call Gemini API ───────────────────────────────────────────────────────
def call_gemini(prompt):
    import requests
    url = (f"https://generativelanguage.googleapis.com/v1/models/"
           f"gemini-2.5-flash:generateContent?key={GEMINI_KEY}")
    body = {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}],
    }
    r = requests.post(url, json=body, timeout=60)
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


# ── Generate markdown report ──────────────────────────────────────────────
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}


def generate_markdown(triage):
    summary = triage.get("summary", {})
    gate = triage.get("gate_recommendation", "FAIL")
    gate_emoji = "🟢 PASS" if gate == "PASS" else "🔴 FAIL"
    findings = [f for f in triage.get("findings", []) if not f.get("false_positive")]
    findings.sort(key=lambda x: x.get("priority", 0), reverse=True)

    lines = [
        "## 🔐 SecureFlow AI — Security Triage Report",
        "",
        f"**Security gate:** {gate_emoji}  ",
        f"> {triage.get('gate_reason', '')}",
        "",
        "| Critical | High | Medium | Actionable | False Positives |",
        "|----------|------|--------|------------|-----------------|",
        f"| {summary.get('critical',0)} | {summary.get('high',0)} | "
        f"{summary.get('medium',0)} | {summary.get('actionable',0)} | "
        f"{summary.get('false_positives',0)} |",
        "",
        "---",
        "",
        "### Prioritized findings",
        "",
    ]

    for f in findings[:10]:
        emoji = SEVERITY_EMOJI.get(f.get("severity", ""), "⚪")
        lines += [
            f"#### {emoji} [{f.get('severity')}] {f.get('title')}",
            f"**Tool:** `{f.get('tool')}` | **Priority:** {f.get('priority')}/10",
            "",
            f"{f.get('description', '')}",
            "",
            f"**Remediation:** {f.get('remediation', '')}",
            "",
            "---",
            "",
        ]

    if triage.get("summary", {}).get("false_positives", 0) > 0:
        lines += [
            "<details>",
            "<summary>False positives suppressed</summary>",
            "",
            "| Finding | Reason |",
            "|---------|--------|",
        ]
        for f in triage.get("findings", []):
            if f.get("false_positive"):
                lines.append(
                    f"| {f.get('title', '')} | {f.get('false_positive_reason', '')} |"
                )
        lines += ["", "</details>", ""]

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    print("Loading scan results from all tools...")
    results = load_all_results()

    if not results:
        print("No scan results found. Creating empty pass report.")
        triage = {
            "summary": {"critical": 0, "high": 0, "medium": 0,
                        "total_raw": 0, "false_positives": 0, "actionable": 0},
            "findings": [],
            "gate_recommendation": "PASS",
            "gate_reason": "No scan results found."
        }
    else:
        print(f"Loaded results from: {list(results.keys())}")
        prompt = build_user_prompt(results)

        print(f"Calling {AI_PROVIDER.upper()} API for triage...")
        if AI_PROVIDER == "gemini":
            raw = call_gemini(prompt)
        else:
            raw = call_claude(prompt)

        # Strip markdown fences if the model added them
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        triage = json.loads(raw)

    # Save JSON output (consumed by security_gate.py)
    with open("triage_output.json", "w") as f:
        json.dump(triage, f, indent=2)

    # Save markdown (posted as PR comment)
    report = generate_markdown(triage)
    with open("triage_report.md", "w") as f:
        f.write(report)

    print(f"Gate recommendation: {triage.get('gate_recommendation')}")
    print(f"Critical: {triage.get('summary',{}).get('critical',0)} | "
          f"High: {triage.get('summary',{}).get('high',0)}")
    print("Triage complete.")


if __name__ == "__main__":
    main()