"""
SecureFlow AI — Security Gate
Reads the AI triage output and enforces pass/fail thresholds.
Exit code 0 = PASS, exit code 1 = FAIL (blocks the build).
"""

import json
import sys

# ── Configurable thresholds ────────────────────────────────────────────────
THRESHOLDS = {
    "critical": 0,    # Zero tolerance for Critical findings
    "high": 3,        # Allow at most 3 High findings
}

# ── Load triage output ─────────────────────────────────────────────────────
try:
    with open("triage_output.json") as f:
        triage = json.load(f)
except FileNotFoundError:
    print("ERROR: triage_output.json not found. AI triage must run first.")
    sys.exit(1)

summary = triage.get("summary", {})
recommendation = triage.get("gate_recommendation", "FAIL")
gate_reason = triage.get("gate_reason", "No reason provided.")

critical = summary.get("critical", 0)
high = summary.get("high", 0)

print("=" * 50)
print("  SecureFlow AI — Security Gate")
print("=" * 50)
print(f"  Critical findings : {critical} (threshold: {THRESHOLDS['critical']})")
print(f"  High findings     : {high} (threshold: {THRESHOLDS['high']})")
print(f"  AI recommendation : {recommendation}")
print(f"  AI reason         : {gate_reason}")
print("=" * 50)

# ── Threshold checks ───────────────────────────────────────────────────────
failures = []

if critical > THRESHOLDS["critical"]:
    failures.append(
        f"Critical findings ({critical}) exceed threshold ({THRESHOLDS['critical']})"
    )

if high > THRESHOLDS["high"]:
    failures.append(
        f"High findings ({high}) exceed threshold ({THRESHOLDS['high']})"
    )

if recommendation == "FAIL":
    failures.append(f"AI triage recommends blocking: {gate_reason}")

# ── Result ─────────────────────────────────────────────────────────────────
if failures:
    print("\n  GATE: FAILED")
    for reason in failures:
        print(f"  ✗ {reason}")
    print("\n  Fix the issues above and re-push to retry.\n")
    sys.exit(1)
else:
    print("\n  GATE: PASSED — build approved for deployment.\n")
    sys.exit(0)