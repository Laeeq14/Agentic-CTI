"""
sigma_validator.py — Deterministic structural validation for LLM-generated Sigma rules.

Sigma rules are YAML documents. This validator checks structural correctness
without executing or compiling the rule, mirroring the approach of validator.py
for YARA-L.

Checks performed:
  1. YAML parses successfully.
  2. Required top-level keys are present: title, logsource, detection, condition.
  3. logsource block contains at least one field (category, product, or service).
  4. detection block contains at least one selection key (not just 'condition').
  5. condition references at least one selection key from the detection block.
  6. No obviously broken condition syntax (bare 'true'/'false').
"""

from __future__ import annotations

import re
from typing import Tuple

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_sigma_from_response(text: str) -> str:
    """
    Strip markdown fences and return the raw Sigma rule YAML.

    The LLM may wrap the rule in ```yaml or ``` fences.

    Args:
        text: Raw LLM response string.

    Returns:
        Cleaned YAML string with fences removed.
    """
    fence_pattern = re.compile(
        r"```(?:yaml|sigma|text|plaintext)?\s*\n?(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    match = fence_pattern.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()


def validate_sigma_rule(rule_text: str) -> Tuple[bool, str]:
    """
    Deterministically validate the structure of an LLM-generated Sigma rule.

    Args:
        rule_text: The raw Sigma rule as a YAML string.

    Returns:
        (True, "") on success.
        (False, "<error message>") on failure.
    """
    if not rule_text or not rule_text.strip():
        return False, "The Sigma rule is empty. Generate a complete Sigma rule YAML."

    errors: list[str] = []

    # ------------------------------------------------------------------
    # Check 1: YAML parses successfully
    # ------------------------------------------------------------------
    parsed: dict = {}
    if _YAML_AVAILABLE:
        try:
            parsed = yaml.safe_load(rule_text)
            if not isinstance(parsed, dict):
                errors.append(
                    "YAML parsed successfully but did not produce a mapping (dict). "
                    "The rule must be a YAML mapping at the top level, not a list or scalar."
                )
        except yaml.YAMLError as exc:
            # Extract the most useful part of the error
            err_str = str(exc)
            errors.append(
                f"YAML syntax error — the rule could not be parsed: {err_str[:300]}"
            )
    else:
        # Fallback: regex-based structural checks if PyYAML is unavailable
        # (shouldn't happen in normal setup, but be defensive)
        if not re.search(r"^\s*title\s*:", rule_text, re.MULTILINE):
            errors.append("Missing 'title:' key.")
        if not re.search(r"^\s*logsource\s*:", rule_text, re.MULTILINE):
            errors.append("Missing 'logsource:' key.")
        if not re.search(r"^\s*detection\s*:", rule_text, re.MULTILINE):
            errors.append("Missing 'detection:' key.")
        if errors:
            return False, _format_errors(errors)
        return True, ""

    if errors:
        # YAML itself is broken — no point running structural checks
        return False, _format_errors(errors)

    # ------------------------------------------------------------------
    # Check 2: Required top-level keys
    # ------------------------------------------------------------------
    required_keys = ["title", "logsource", "detection", "condition"]
    # Note: 'condition' is often inside 'detection' in Sigma v1 but is sometimes
    # promoted to top-level by LLMs. We check both locations.
    detection_block = parsed.get("detection", {}) or {}
    condition_value = parsed.get("condition") or detection_block.get("condition")

    for key in ["title", "logsource", "detection"]:
        if key not in parsed:
            errors.append(
                f"Missing required top-level key: '{key}'. "
                f"A Sigma rule must have at minimum: title, logsource, detection (with condition)."
            )

    if not condition_value:
        errors.append(
            "Missing 'condition' field. It must appear either inside the 'detection:' block "
            "or as a top-level key. Example: condition: selection"
        )

    if errors:
        return False, _format_errors(errors)

    # ------------------------------------------------------------------
    # Check 3: logsource block has at least one field
    # ------------------------------------------------------------------
    logsource = parsed.get("logsource", {}) or {}
    if not isinstance(logsource, dict) or not any(
        k in logsource for k in ("category", "product", "service")
    ):
        errors.append(
            "The 'logsource:' block must contain at least one of: category, product, service. "
            "Example:\n  logsource:\n    category: network_connection\n    product: windows"
        )

    # ------------------------------------------------------------------
    # Check 4: detection block has at least one selection key
    # ------------------------------------------------------------------
    if isinstance(detection_block, dict):
        selection_keys = [
            k for k in detection_block.keys()
            if k != "condition" and not k.startswith("filter")
        ]
        if not selection_keys:
            errors.append(
                "The 'detection:' block has no selection keys. "
                "Add at least one named selection (e.g., 'selection:', 'keywords:', 'net_connection:') "
                "that defines the matching criteria."
            )

        # ------------------------------------------------------------------
        # Check 5: condition references a valid selection key
        # ------------------------------------------------------------------
        if condition_value and selection_keys:
            condition_str = str(condition_value).strip()
            referenced = any(
                sel in condition_str
                for sel in selection_keys
            )
            if not referenced:
                errors.append(
                    f"The 'condition' value '{condition_str[:80]}' does not reference any "
                    f"detection selection key. Available keys: {selection_keys}. "
                    f"Example: condition: selection"
                )

        # ------------------------------------------------------------------
        # Check 6: condition is not a bare boolean
        # ------------------------------------------------------------------
        if condition_value in (True, False, "true", "false"):
            errors.append(
                "The 'condition' value is a bare boolean. "
                "It must reference a selection key (e.g., 'condition: selection') "
                "or a logical expression (e.g., 'condition: selection and not filter')."
            )

    if errors:
        return False, _format_errors(errors)

    return True, ""


def _format_errors(errors: list[str]) -> str:
    return (
        f"Sigma validation failed with {len(errors)} error(s):\n"
        + "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))
        + "\n\nPlease fix ALL issues and regenerate the complete Sigma rule YAML."
    )


# ---------------------------------------------------------------------------
# Quick self-test (run: python sigma_validator.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    GOOD_RULE = """
title: APT41 KEYPLUG C2 Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects network connections to known APT41 KEYPLUG C2 infrastructure
author: Agentic-CTI
date: 2024-01-01
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationHostname|contains:
      - 'evil-apt41.com'
      - 'apt41-c2.net'
  condition: selection
falsepositives:
  - Legitimate traffic to these domains (verify before blocking)
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
"""

    BAD_NO_CONDITION = """
title: Bad Rule
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationHostname: evil.com
"""

    BAD_NO_SELECTION = """
title: Bad Rule 2
logsource:
  category: process_creation
  product: windows
detection:
  condition: selection
"""

    for label, rule in [
        ("GOOD RULE", GOOD_RULE),
        ("BAD: no condition", BAD_NO_CONDITION),
        ("BAD: no selection", BAD_NO_SELECTION),
    ]:
        valid, err = validate_sigma_rule(rule)
        status = "PASS" if valid else "FAIL"
        print(f"\n[{label}] -> {status}")
        if err:
            print(err)
