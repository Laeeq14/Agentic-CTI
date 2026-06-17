"""
validator.py — Deterministic YARA-L 2.0 structural validation guardrail.

This module provides rule-based validation of LLM-generated YARA-L 2.0 rules,
completely independent of any LLM. It acts as a guardrail that routes failed
rules back to the LLM with a precise, actionable error message.
"""

import re
from typing import Tuple


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_yaral_from_response(text: str) -> str:
    """
    Strip markdown code fences and extract the raw YARA-L rule text.

    The LLM may wrap the rule in ```yara-l or ``` fences. This function
    strips them to produce a clean string for further validation.

    Args:
        text: Raw LLM response string, possibly containing markdown fences.

    Returns:
        Cleaned rule string with fences removed and leading/trailing
        whitespace stripped.
    """
    # Match optional language tag after the opening fence
    fence_pattern = re.compile(
        r"```(?:yara-?l|yaral|text|plaintext)?\s*\n?(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    match = fence_pattern.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()


def validate_yaral_rule(rule_text: str) -> Tuple[bool, str]:
    """
    Deterministically validate the structure of a YARA-L 2.0 rule.

    Checks performed (in order):
    1. The 'rule' keyword and a rule name are present.
    2. Braces are balanced (same number of '{' and '}').
    3. The 'meta:' section exists inside the rule body.
    4. The 'events:' section exists inside the rule body.
    5. The 'condition:' section exists inside the rule body.
    6. At least one event variable ($e., $e2., etc.) is declared in events:.
    7. The same event variable is referenced in condition:.
    8. The meta section contains required fields (author, description).

    Args:
        rule_text: The raw YARA-L 2.0 rule as a string.

    Returns:
        A tuple of (is_valid: bool, error_message: str).
        On success: (True, "")
        On failure: (False, "<human-readable error for LLM re-prompt>")
    """
    if not rule_text or not rule_text.strip():
        return False, "The rule is empty. Generate a complete YARA-L 2.0 rule."

    errors: list[str] = []

    # ------------------------------------------------------------------
    # Check 1: 'rule' keyword and rule name
    # ------------------------------------------------------------------
    rule_header = re.search(r"\brule\s+(\w+)\s*\{", rule_text)
    if not rule_header:
        errors.append(
            "Missing 'rule <name> {' header. The rule must start with "
            "'rule <snake_case_name> {'."
        )

    # ------------------------------------------------------------------
    # Check 2: Balanced braces
    # ------------------------------------------------------------------
    open_braces = rule_text.count("{")
    close_braces = rule_text.count("}")
    if open_braces != close_braces:
        errors.append(
            f"Unbalanced braces: found {open_braces} opening '{{' and "
            f"{close_braces} closing '}}'. Every opening brace must have a "
            "matching closing brace."
        )

    # ------------------------------------------------------------------
    # Check 3: Required sections — meta, events, condition
    # ------------------------------------------------------------------
    required_sections = {
        "meta": re.compile(r"\bmeta\s*:", re.IGNORECASE),
        "events": re.compile(r"\bevents\s*:", re.IGNORECASE),
        "condition": re.compile(r"\bcondition\s*:", re.IGNORECASE),
    }
    for section_name, pattern in required_sections.items():
        if not pattern.search(rule_text):
            errors.append(
                f"Missing '{section_name}:' section. YARA-L 2.0 rules MUST "
                f"contain a '{section_name}:' block."
            )

    # ------------------------------------------------------------------
    # Check 4: Event variables declared in events: block
    # ------------------------------------------------------------------
    # Extract the events block content
    events_match = re.search(
        r"\bevents\s*:(.*?)(?=\bcondition\s*:|$)", rule_text, re.DOTALL | re.IGNORECASE
    )
    event_vars_in_events: set[str] = set()
    if events_match:
        events_block = events_match.group(1)
        # Find all event variable references like $e, $e2, $network, etc.
        event_vars_in_events = set(
            re.findall(r"(\$[a-zA-Z][a-zA-Z0-9_]*)\.", events_block)
        )
        if not event_vars_in_events:
            errors.append(
                "No UDM event variable references found in the 'events:' block. "
                "You must reference at least one event variable (e.g., $e.metadata.event_type). "
                "All UDM field accesses must use the '$variablename.' prefix."
            )

    # ------------------------------------------------------------------
    # Check 5: Event variables referenced in condition: block
    # ------------------------------------------------------------------
    condition_match = re.search(
        r"\bcondition\s*:(.*?)(?=\}|$)", rule_text, re.DOTALL | re.IGNORECASE
    )
    if condition_match:
        condition_block = condition_match.group(1)
        event_vars_in_condition: set[str] = set()

        # Check for bare variable references like "$e" or "$e and $e2"
        event_vars_in_condition = set(
            re.findall(r"(\$[a-zA-Z][a-zA-Z0-9_]*)", condition_block)
        )

        if not event_vars_in_condition:
            errors.append(
                "The 'condition:' block is empty or contains no event variable references. "
                "The condition must reference at least one event variable (e.g., 'condition: $e')."
            )
        elif event_vars_in_events and not event_vars_in_events.intersection(
            event_vars_in_condition
        ):
            declared = ", ".join(sorted(event_vars_in_events))
            errors.append(
                f"Event variable(s) declared in 'events:' ({declared}) are not "
                "referenced in the 'condition:' block. "
                f"Add '{declared}' to the condition (e.g., 'condition: {next(iter(event_vars_in_events))}')."
            )
    elif "condition" not in rule_text.lower():
        # condition section missing — already caught above, skip
        pass

    # ------------------------------------------------------------------
    # Check 6: meta section contains required fields
    # ------------------------------------------------------------------
    meta_match = re.search(
        r"\bmeta\s*:(.*?)(?=\bevents\s*:|$)", rule_text, re.DOTALL | re.IGNORECASE
    )
    if meta_match:
        meta_block = meta_match.group(1)
        if not re.search(r"\bauthor\s*=", meta_block, re.IGNORECASE):
            errors.append(
                "The 'meta:' section is missing the 'author' field. "
                "Add: author = \"Agentic-CTI\""
            )
        if not re.search(r"\bdescription\s*=", meta_block, re.IGNORECASE):
            errors.append(
                "The 'meta:' section is missing the 'description' field. "
                "Add a descriptive description = \"...\" field."
            )

    # ------------------------------------------------------------------
    # Final result
    # ------------------------------------------------------------------
    if errors:
        error_summary = (
            f"Validation failed with {len(errors)} error(s):\n"
            + "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))
            + "\n\nPlease fix ALL of the above issues and regenerate the complete rule."
        )
        return False, error_summary

    return True, ""


# ---------------------------------------------------------------------------
# Quick self-test (run: python validator.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    # Ensure UTF-8 output on Windows terminals
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    GOOD_RULE = """
rule apt41_process_launch_detection {
  meta:
    author = "Agentic-CTI"
    description = "Detects APT41 process launch patterns based on known TTPs"
    severity = "HIGH"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /.*cobalt.*strike.*/

  condition:
    $e
}
"""

    BAD_RULE_NO_CONDITION = """
rule bad_rule {
  meta:
    author = "Agentic-CTI"
    description = "Broken rule"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
}
"""

    BAD_RULE_NO_EVENT_VAR = """
rule bad_rule2 {
  meta:
    author = "Agentic-CTI"
    description = "No UDM variables"

  events:
    metadata.event_type = "PROCESS_LAUNCH"

  condition:
    true
}
"""

    for label, rule in [
        ("GOOD RULE", GOOD_RULE),
        ("BAD: no condition", BAD_RULE_NO_CONDITION),
        ("BAD: no event variable", BAD_RULE_NO_EVENT_VAR),
    ]:
        valid, err = validate_yaral_rule(rule)
        status = "PASS" if valid else "FAIL"
        print(f"\n[{label}] -> {status}")
        if err:
            print(err)
