"""
tests/eval/fp_evaluator.py — False-positive rate evaluation for generated detection rules.

Checks whether a YARA-L, Sigma, or KQL detection rule would fire on the benign traffic
dataset (data/logs/benign_traffic.json). Since we can't run a full YARA-L interpreter,
this is a heuristic evaluator that parses IOC patterns from the rule text and checks
each benign event's domain, IP, and hash fields against those patterns.

Scope:
  - Checks domain/IP regex patterns from re.regex() calls in YARA-L rules
  - Checks IP literal matches ($e.target.ip = "x.x.x.x")
  - Checks hash values from $e.principal.process.file.sha256 in() blocks
  - Works correctly for IOC-pattern rules (the primary content Agentic-CTI generates)
  - Does NOT simulate full UDM event_type matching (out of scope — would require
    a full YARA-L interpreter)

This is the correct scope: a detection rule fires a false positive if an attacker-IOC
pattern accidentally matches a benign domain/IP, regardless of event_type. The
FP rate here measures IOC pattern hygiene, not event_type filtering precision.

Usage:
    from tests.eval.fp_evaluator import run_fp_check

    result = run_fp_check(yaral_rule_text)
    # result = {
    #     "fp_count": 2,
    #     "fp_rate": 0.016,
    #     "total_benign_events": 125,
    #     "fp_event_ids": ["B034", "B071"],
    #     "fp_domains_matched": ["cdn.jsdelivr.net"],
    #     "error": None
    # }
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load benign event dataset once at module import
# ---------------------------------------------------------------------------

_BENIGN_DATASET_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "logs" / "benign_traffic.json"
_BENIGN_EVENTS: list[dict] = []

try:
    with open(_BENIGN_DATASET_PATH, "r", encoding="utf-8") as _f:
        _BENIGN_EVENTS = json.load(_f)
    logger.info("FP Evaluator: loaded %d benign events from %s", len(_BENIGN_EVENTS), _BENIGN_DATASET_PATH)
except FileNotFoundError:
    logger.warning("FP Evaluator: benign_traffic.json not found at %s — FP checks will return None.", _BENIGN_DATASET_PATH)
except json.JSONDecodeError as exc:
    logger.error("FP Evaluator: failed to parse benign_traffic.json: %s", exc)


# ---------------------------------------------------------------------------
# Threshold gate: rules above this FP rate are flagged as needs_review
# ---------------------------------------------------------------------------

FP_RATE_THRESHOLD: float = 0.05  # 5% -- rules that match >5% of benign events
                                   # should be reviewed before deployment.
                                   # Rationale: SOC teams budget ~3-5% FP tolerance;
                                   # above that, alert fatigue degrades analyst trust.


# ---------------------------------------------------------------------------
# YARA-L IOC pattern extraction
# ---------------------------------------------------------------------------

def _extract_domain_patterns_from_yaral(rule_text: str) -> list[str]:
    """
    Extract all domain/hostname regex patterns from a YARA-L rule's re.regex() calls.

    Returns a list of raw pattern strings (from inside the backtick literal).
    Example: re.regex($e.target.domain.name, `evil\\.com|bad\\.net`) -> ["evil\\.com", "bad\\.net"]
    """
    patterns: list[str] = []
    # Match re.regex($e.<field>, `<pattern>`) calls — backtick delimited
    regex_calls = re.findall(
        r"re\.regex\s*\([^,]+,\s*`([^`]+)`\)",
        rule_text,
        re.IGNORECASE,
    )
    for raw_pattern in regex_calls:
        # Split the | alternation into individual patterns
        sub_patterns = [p.strip() for p in raw_pattern.split("|") if p.strip()]
        patterns.extend(sub_patterns)
    return patterns


def _extract_ip_literals_from_yaral(rule_text: str) -> list[str]:
    """
    Extract IP literal values from YARA-L $e.target.ip = "x.x.x.x" assignments.
    """
    return re.findall(
        r'\$e\.target\.ip\s*=\s*"([^"]+)"',
        rule_text,
        re.IGNORECASE,
    )


def _extract_hash_values_from_yaral(rule_text: str) -> list[str]:
    """
    Extract SHA256 hash values from YARA-L in() blocks.
    """
    # Match the in (...) block containing quoted hashes
    in_block_match = re.search(
        r"\.sha256\s+in\s*\((.*?)\)",
        rule_text,
        re.DOTALL | re.IGNORECASE,
    )
    if not in_block_match:
        return []
    block = in_block_match.group(1)
    return re.findall(r'"([a-fA-F0-9]{32,64})"', block)


# ---------------------------------------------------------------------------
# Sigma rule IOC extraction
# ---------------------------------------------------------------------------

def _extract_iocs_from_sigma(rule_text: str) -> tuple[list[str], list[str], list[str]]:
    """
    Extract domain patterns, IPs, and hashes from a Sigma rule YAML.

    Parses the detection block's selection entries looking for:
    - DestinationHostname|contains: [list] -> domain literals
    - DestinationIp|contains: [list] -> IP literals
    - Hashes|contains: [list of SHA256=/MD5= prefixed hashes]
    - QueryName|contains: [list] -> DNS query domains

    Returns (domains, ips, hashes) as lists of strings.
    """
    domains: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []

    try:
        import yaml
        parsed = yaml.safe_load(rule_text)
        if not isinstance(parsed, dict):
            return domains, ips, hashes

        detection = parsed.get("detection", {})
        if not isinstance(detection, dict):
            return domains, ips, hashes

        # Walk all selection blocks (any key except 'condition')
        for key, block in detection.items():
            if key == "condition" or not isinstance(block, dict):
                continue
            for field, values in block.items():
                if not isinstance(values, list):
                    values = [values]
                field_lower = field.lower()
                for val in values:
                    if val is None:
                        continue
                    val_str = str(val)
                    if any(f in field_lower for f in ("hostname", "queryname", "host", "url", "requesturl")):
                        domains.append(val_str.lower())
                    elif any(f in field_lower for f in ("ip", "address")):
                        ips.append(val_str)
                    elif "hash" in field_lower:
                        # Strip SHA256= / MD5= prefix if present
                        clean = re.sub(r'^(?:SHA256|MD5|SHA1)=', '', val_str, flags=re.IGNORECASE)
                        hashes.append(clean.lower())
    except Exception:
        pass  # YAML parse failure -- return empty lists

    return domains, ips, hashes


# ---------------------------------------------------------------------------
# KQL IOC extraction
# ---------------------------------------------------------------------------

def _extract_iocs_from_kql(query_text: str) -> tuple[list[str], list[str], list[str]]:
    """
    Extract IOC values from a KQL query's dynamic() array declarations.

    Targets the pattern:
      let malicious_domains = dynamic(["domain1", "domain2"]);
      let malicious_ips = dynamic(["1.2.3.4"]);
      let malicious_hashes = dynamic(["abc123..."]);

    Returns (domains, ips, hashes).
    """
    domains: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []

    # Match: let malicious_<type> = dynamic([...]);
    array_pattern = re.compile(
        r'let\s+malicious_(\w+)\s*=\s*dynamic\(\[(.*?)\]\)',
        re.DOTALL | re.IGNORECASE,
    )

    for match in array_pattern.finditer(query_text):
        var_type = match.group(1).lower()  # domains, ips, hashes
        raw_block = match.group(2)
        values = re.findall(r'"([^"]+)"', raw_block)

        if "domain" in var_type or "url" in var_type:
            domains.extend(v.lower() for v in values if v.strip())
        elif "ip" in var_type or "address" in var_type:
            ips.extend(v for v in values if v.strip())
        elif "hash" in var_type:
            hashes.extend(v.lower() for v in values if v.strip())

    return domains, ips, hashes


# ---------------------------------------------------------------------------
# Benign event field extraction
# ---------------------------------------------------------------------------

def _get_event_domains(event: dict) -> list[str]:
    """Return all domain/hostname fields from a benign event."""
    domains = []
    for field in ("domain", "dest_ip"):
        val = event.get(field, "")
        if val:
            domains.append(str(val).lower())
    return domains


def _get_event_ips(event: dict) -> list[str]:
    """Return all IP fields from a benign event."""
    ips = []
    for field in ("dest_ip", "source_ip"):
        val = event.get(field, "")
        if val:
            ips.append(str(val))
    return ips


def _get_event_hashes(event: dict) -> list[str]:
    """Return all hash fields from a benign event."""
    hashes = []
    for field in ("file_hash_sha256", "file_hash_md5"):
        val = event.get(field, "")
        if val:
            hashes.append(str(val).lower())
    return hashes


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def _domain_matches_any_pattern(domain: str, patterns: list[str]) -> Optional[str]:
    """
    Return the first matching pattern if the domain matches any YARA-L regex pattern.
    Returns None if no match.

    Handles the YARA-L regex escaping convention (e.g., escaped dots).
    """
    for pattern in patterns:
        try:
            # YARA-L patterns escape dots as \. — convert to valid Python regex
            py_pattern = pattern.replace("\\.", r"\.")
            if re.search(py_pattern, domain, re.IGNORECASE):
                return pattern
        except re.error:
            # Malformed regex — skip
            continue
    return None


def _ip_matches_any_literal(ip: str, ip_literals: list[str]) -> bool:
    """Return True if the IP exactly matches any literal from the rule."""
    return ip in ip_literals


def _hash_matches_any(hash_val: str, rule_hashes: list[str]) -> bool:
    """Return True if the hash (lowercased) matches any hash in the rule."""
    return hash_val.lower() in {h.lower() for h in rule_hashes}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_fp_check(
    rule_text: str,
    benign_events: Optional[list[dict]] = None,
    fmt: str = "yaral",
) -> dict:
    """
    Run a false-positive check on a detection rule against benign traffic.

    Supports three rule formats:
      fmt='yaral'  -- YARA-L 2.0 (Google SecOps): parses re.regex() calls and ip literals
      fmt='sigma'  -- Sigma YAML: parses detection block selection entries
      fmt='kql'    -- KQL (Microsoft Sentinel): parses let malicious_* = dynamic([...])

    The check is scoped to IOC pattern hygiene: a rule fires a false positive if
    an attacker-IOC pattern matches a benign domain/IP/hash, regardless of
    event_type filtering. This measures whether the IOC list itself is clean.

    Args:
        rule_text:      The detection rule text to evaluate.
        benign_events:  Optional override for the benign event dataset.
        fmt:            Rule format: 'yaral' (default), 'sigma', or 'kql'.

    Returns:
        Dict with keys:
          fp_count           : int   -- number of benign events that match an IOC pattern
          fp_rate            : float -- fp_count / total_benign_events
          total_benign_events: int
          fp_event_ids       : list[str] -- event IDs of FP hits
          fp_domains_matched : list[str] -- which patterns caused FP hits
          needs_review       : bool  -- True if fp_rate > FP_RATE_THRESHOLD (5%)
          format             : str   -- which format was evaluated
          error              : str | None
    """
    events = benign_events if benign_events is not None else _BENIGN_EVENTS

    if not events:
        return {
            "fp_count": None, "fp_rate": None, "total_benign_events": 0,
            "fp_event_ids": [], "fp_domains_matched": [],
            "needs_review": None, "format": fmt,
            "error": "Benign dataset not loaded -- check data/logs/benign_traffic.json.",
        }

    if not rule_text or not rule_text.strip():
        return {
            "fp_count": None, "fp_rate": None, "total_benign_events": len(events),
            "fp_event_ids": [], "fp_domains_matched": [],
            "needs_review": None, "format": fmt,
            "error": "Rule text is empty.",
        }

    try:
        # Extract IOC patterns based on format
        fmt_lower = fmt.lower()
        if fmt_lower == "sigma":
            domain_patterns, ip_literals, rule_hashes = _extract_iocs_from_sigma(rule_text)
            # For Sigma, domain_patterns are literals -- convert to simple patterns
            # (no regex, just substring match against benign event domain field)
            use_literal_domains = True
        elif fmt_lower == "kql":
            domain_patterns, ip_literals, rule_hashes = _extract_iocs_from_kql(rule_text)
            use_literal_domains = True
        else:  # yaral (default)
            domain_patterns = _extract_domain_patterns_from_yaral(rule_text)
            ip_literals = _extract_ip_literals_from_yaral(rule_text)
            rule_hashes = _extract_hash_values_from_yaral(rule_text)
            use_literal_domains = False

        fp_event_ids: list[str] = []
        fp_domains_matched: set[str] = set()

        for event in events:
            event_id = event.get("event_id", "?")
            matched = False

            # Check domains
            for domain in _get_event_domains(event):
                if use_literal_domains:
                    # Literal substring match (Sigma/KQL use exact domain strings)
                    for pat in domain_patterns:
                        if pat and pat in domain:
                            matched = True
                            fp_domains_matched.add(pat)
                            break
                else:
                    # Regex match (YARA-L uses re.regex() patterns)
                    hit = _domain_matches_any_pattern(domain, domain_patterns)
                    if hit:
                        matched = True
                        fp_domains_matched.add(hit)
                        break
                if matched:
                    break

            # Check IPs
            if not matched and ip_literals:
                for ip in _get_event_ips(event):
                    if _ip_matches_any_literal(ip, ip_literals):
                        matched = True
                        fp_domains_matched.add(f"IP:{ip}")
                        break

            # Check hashes
            if not matched and rule_hashes:
                for h in _get_event_hashes(event):
                    if _hash_matches_any(h, rule_hashes):
                        matched = True
                        fp_domains_matched.add(f"HASH:{h[:16]}...")
                        break

            if matched:
                fp_event_ids.append(event_id)

        fp_count = len(fp_event_ids)
        fp_rate = round(fp_count / len(events), 4) if events else 0.0
        needs_review = fp_rate > FP_RATE_THRESHOLD

        return {
            "fp_count": fp_count,
            "fp_rate": fp_rate,
            "total_benign_events": len(events),
            "fp_event_ids": fp_event_ids,
            "fp_domains_matched": sorted(fp_domains_matched),
            "needs_review": needs_review,
            "format": fmt,
            "error": None,
        }

    except Exception as exc:
        logger.exception("FP check failed: %s", exc)
        return {
            "fp_count": None, "fp_rate": None, "total_benign_events": len(events),
            "fp_event_ids": [], "fp_domains_matched": [],
            "needs_review": None, "format": fmt,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Quick self-test (run: python tests/eval/fp_evaluator.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Rule targeting clearly malicious domains — should have 0 FPs
    CLEAN_RULE = """
rule apt41_c2_detection {
  meta:
    author = "Agentic-CTI"
    description = "Detects APT41 C2 traffic"
    severity = "HIGH"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    (
      re.regex($e.target.domain.name, `evil-apt41\\.com|apt41-c2\\.net`) nocase or
      $e.target.ip = "203.0.113.45"
    )

  condition:
    $e
}
"""

    # Rule with a domain that overlaps with benign traffic (cdn.jsdelivr.net contains "cdn")
    NOISY_RULE = """
rule noisy_detection {
  meta:
    author = "Agentic-CTI"
    description = "Overly broad rule — will FP"
    severity = "HIGH"
    yara_version = "YL2.0"
    rule_version = "1.0"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    (
      re.regex($e.target.domain.name, `google\\.com|microsoft\\.com`) nocase
    )

  condition:
    $e
}
"""

    for label, rule in [("CLEAN RULE", CLEAN_RULE), ("NOISY RULE", NOISY_RULE)]:
        result = run_fp_check(rule)
        print(f"\n[{label}]")
        print(f"  FP count:  {result['fp_count']}")
        print(f"  FP rate:   {result['fp_rate']}")
        print(f"  FP events: {result['fp_event_ids'][:5]}")
        print(f"  Patterns:  {result['fp_domains_matched'][:5]}")
        if result["error"]:
            print(f"  Error:     {result['error']}")
