"""
ETH-Check Output Parser
=======================
Parses real output from:
  - Slither  → produced by: slither <contract>.sol --json <output>.json
  - Mythril  → produced by: SmartBugs result.log (JSON lines format)

Normalises both into a unified Finding dataclass for LLM deduplication.

Usage:
    python parser.py --slither out/SimpleDAO_slither.json \
                     --mythril path/to/result.log \
                     --out out/SimpleDAO_combined.json
"""

import json
import argparse
from dataclasses import dataclass, asdict
from typing import Optional

# ── EthTrust-SL P-category mapping ───────────────────────────────────────────
# Maps Slither detector names and Mythril SWC IDs to EthTrust-SL rule codes.
# Based on Table 3 of the ETH-Check paper (Zheng & Hu, 2025).

SLITHER_TO_ETHTRUST = {
    # P1 - Reentrancy
    "reentrancy-eth":        "P1",
    "reentrancy-benign":     "P1",
    "reentrancy-no-eth":     "P1",
    "reentrancy-events":     "P1",
    # P2 - Access control
    "missing-zero-check":    "P2",
    "tx-origin":             "P2",
    "incorrect-modifier":    "P2",
    # P3 - Timestamp / randomness
    "timestamp":             "P3",
    "weak-prng":             "P4",
    # P4 - Integer safety
    "arithmetic":            "P4",
    # P5 - Gas DoS
    "costly-loop":           "P5",
    "unbounded-loop":        "P5",
    # P8 - Unsafe external calls
    "low-level-calls":       "P8",
    "unchecked-send":        "P8",
    "unchecked-transfer":    "P8",
    # P9 - Unchecked return values
    "unchecked-lowlevel":    "P9",
    "unused-return":         "P9",
    # P11 - Deprecated constructs
    "deprecated-standards":  "P11",
    # P12 - Shadowing
    "shadowing-local":       "P12",
    "shadowing-state":       "P12",
    # P15 - Compiler versioning
    "solc-version":          "P15",
    "pragma":                "P15",
}

MYTHRIL_SWC_TO_ETHTRUST = {
    "107": "P1",   # Reentrancy
    "105": "P2",   # Unprotected Ether Withdrawal (access control adjacent)
    "104": "P9",   # Unchecked return value
    "101": "P4",   # Integer overflow/underflow
    "106": "P3",   # Unprotected SELFDESTRUCT
    "114": "P3",   # Timestamp dependence
    "120": "P4",   # Weak randomness
    "116": "P5",   # Gas DoS
    "103": "P8",   # Floating pragma (maps loosely)
    "111": "P8",   # Use of deprecated functions
}


@dataclass
class Finding:
    """Unified finding from any tool, ready for LLM deduplication."""
    tool: str                    # "slither" or "mythril"
    check: str                   # detector name (slither) or title (mythril)
    swc_id: Optional[str]        # SWC registry ID if available
    ethtrust_rule: str           # P1–P15 mapped category
    severity: str                # high / medium / low / informational
    contract: Optional[str]      # contract name
    function: Optional[str]      # function name
    lines: list                  # line numbers affected
    description: str             # human-readable finding description
    raw: dict                    # original data preserved for LLM context


# ── Slither Parser ─────────────────────────────────────────────────────────────

def parse_slither(json_path: str) -> list[Finding]:
    """
    Parse Slither --json output into Finding objects.

    Slither JSON structure:
      {
        "success": true,
        "results": {
          "detectors": [
            {
              "check": "reentrancy-eth",
              "impact": "High",
              "confidence": "Medium",
              "description": "...",
              "elements": [ { "type": "function", "name": "...", "source_mapping": {...} } ]
            }
          ]
        }
      }
    """
    with open(json_path) as f:
        data = json.load(f)

    if not data.get("success"):
        print(f"[WARN] Slither reported failure in {json_path}")
        return []

    findings = []
    for det in data.get("results", {}).get("detectors", []):
        check = det.get("check", "unknown")
        impact = det.get("impact", "Unknown").lower()

        # Extract function name and lines from elements
        function_name = None
        lines = []
        for el in det.get("elements", []):
            if el.get("type") == "function" and not function_name:
                function_name = el.get("name")
            sm = el.get("source_mapping", {})
            lines.extend(sm.get("lines", []))
        lines = sorted(set(lines))  # deduplicate line numbers

        # Extract contract name from first element's parent
        contract_name = None
        elements = det.get("elements", [])
        if elements:
            parent = elements[0].get("type_specific_fields", {}).get("parent", {})
            if parent.get("type") == "contract":
                contract_name = parent.get("name")

        ethtrust = SLITHER_TO_ETHTRUST.get(check, "P0")  # P0 = unmapped

        findings.append(Finding(
            tool="slither",
            check=check,
            swc_id=None,  # Slither doesn't use SWC IDs natively
            ethtrust_rule=ethtrust,
            severity=impact,
            contract=contract_name,
            function=function_name,
            lines=lines,
            description=det.get("description", "").strip(),
            raw=det,
        ))

    return findings


# ── Mythril Parser ─────────────────────────────────────────────────────────────

def parse_mythril(log_path: str) -> list[Finding]:
    """
    Parse Mythril result.log (SmartBugs format) into Finding objects.

    Mythril log structure (single JSON object):
      {
        "success": true,
        "issues": [
          {
            "title": "External Call To User-Supplied Address",
            "swc-id": "107",
            "severity": "Low",
            "description": "...",
            "contract": "SimpleDAO",
            "function": "withdraw(uint256)",
            "lineno": 19,
            "code": "msg.sender.call.value(amount)()"
          }
        ]
      }
    """
    with open(log_path) as f:
        data = json.load(f)

    if not data.get("success"):
        print(f"[WARN] Mythril reported failure in {log_path}")
        return []

    findings = []
    for issue in data.get("issues", []):
        swc_id = str(issue.get("swc-id", ""))
        severity = issue.get("severity", "Unknown").lower()
        lineno = issue.get("lineno")
        lines = [lineno] if lineno else []

        ethtrust = MYTHRIL_SWC_TO_ETHTRUST.get(swc_id, "P0")

        findings.append(Finding(
            tool="mythril",
            check=issue.get("title", "unknown"),
            swc_id=swc_id if swc_id else None,
            ethtrust_rule=ethtrust,
            severity=severity,
            contract=issue.get("contract"),
            function=issue.get("function"),
            lines=lines,
            description=issue.get("description", "").strip(),
            raw={k: v for k, v in issue.items() if k != "tx_sequence"},  # skip bytecode noise
        ))

    return findings


# ── Combined Output ────────────────────────────────────────────────────────────

def combine_and_save(slither_findings: list, mythril_findings: list, out_path: str):
    """Combine findings from both tools and write to JSON for LLM input."""
    all_findings = slither_findings + mythril_findings

    output = {
        "total_findings": len(all_findings),
        "slither_count": len(slither_findings),
        "mythril_count": len(mythril_findings),
        "findings": [asdict(f) for f in all_findings],
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[OK] Combined {len(all_findings)} findings → {out_path}")
    print(f"     Slither: {len(slither_findings)} | Mythril: {len(mythril_findings)}")
    print(f"\n[SUMMARY] Findings by EthTrust rule:")

    # Quick summary by rule
    rule_counts = {}
    for finding in all_findings:
        rule = finding.ethtrust_rule
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
    for rule, count in sorted(rule_counts.items()):
        print(f"  {rule}: {count} alert(s)")

    print(f"\n[PREVIEW] This is the cascading alert problem:")
    print(f"  {len(all_findings)} total alerts → likely {len(rule_counts)} unique vulnerability categories")
    print(f"  LLM deduplication target: collapse to true unique vulnerabilities")


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Slither + Mythril output into unified findings JSON")
    parser.add_argument("--slither", help="Path to Slither --json output file")
    parser.add_argument("--mythril", help="Path to Mythril result.log file")
    parser.add_argument("--out", default="data/combined/combined_findings.json", help="Output JSON path")
    args = parser.parse_args()

    slither_findings = []
    mythril_findings = []

    if args.slither:
        print(f"[1] Parsing Slither: {args.slither}")
        slither_findings = parse_slither(args.slither)
        print(f"    → {len(slither_findings)} findings")

    if args.mythril:
        print(f"[2] Parsing Mythril: {args.mythril}")
        mythril_findings = parse_mythril(args.mythril)
        print(f"    → {len(mythril_findings)} findings")

    if not slither_findings and not mythril_findings:
        print("[ERR] No input files provided. Use --slither and/or --mythril")
        exit(1)

    combine_and_save(slither_findings, mythril_findings, args.out)