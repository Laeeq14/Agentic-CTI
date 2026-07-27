"""
src/ttp_logsource_map.py — TTP-to-logsource routing for multi-format rule generation.

Maps MITRE ATT&CK technique IDs to:
  - Sigma logsource categories (category/product/service)
  - Sentinel KQL table + filter hints

Design: logsource is looked up by TTP prefix, so T1059.001 matches the
T1059 entry. The map is intentionally a plain dict — add entries here to
expand coverage without touching any generation node logic.

Usage:
    from src.ttp_logsource_map import resolve_logsource, resolve_kql_table

    logsource = resolve_logsource(["T1059.001", "T1071.001"])
    # → {"category": "process_creation", "product": "windows"}

    kql_table = resolve_kql_table(["T1071.001", "T1041"])
    # → "CommonSecurityLog"
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# TTP → Sigma logsource
# ---------------------------------------------------------------------------
# Keys are TTP prefixes (matched longest-first against the technique ID).
# Values are Sigma logsource dicts.
#
# Category reference:
#   process_creation   — new process spawned (Sysmon Event 1, Security 4688)
#   network_connection — outbound/inbound TCP/UDP connection (Sysmon Event 3)
#   dns_query          — DNS lookup (Sysmon Event 22)
#   file_event         — file created/modified/deleted (Sysmon Event 11)
#   registry_event     — registry key/value create/modify (Sysmon Event 12/13)
#   image_load         — DLL/driver loaded (Sysmon Event 7)
#   pipe_created       — named pipe created (Sysmon Event 17)
# ---------------------------------------------------------------------------

_TTP_TO_SIGMA_LOGSOURCE: dict[str, dict[str, str]] = {
    # Execution — scripting / command interpreters
    "T1059":    {"category": "process_creation", "product": "windows"},
    "T1047":    {"category": "process_creation", "product": "windows"},   # WMI
    "T1053":    {"category": "process_creation", "product": "windows"},   # Scheduled Task
    "T1569":    {"category": "process_creation", "product": "windows"},   # System Service

    # Initial Access / Phishing — delivered as process (macro execution)
    "T1566":    {"category": "process_creation", "product": "windows"},

    # Persistence
    "T1547":    {"category": "registry_event",   "product": "windows"},   # Registry Run Key
    "T1543":    {"category": "process_creation", "product": "windows"},   # Create/Modify Service
    "T1037":    {"category": "process_creation", "product": "windows"},   # Boot/Logon Scripts

    # Defense Evasion
    "T1036":    {"category": "process_creation", "product": "windows"},   # Masquerading
    "T1027":    {"category": "file_event",       "product": "windows"},   # Obfuscation
    "T1055":    {"category": "process_creation", "product": "windows"},   # Process Injection
    "T1218":    {"category": "process_creation", "product": "windows"},   # Signed Binary Proxy
    "T1070":    {"category": "process_creation", "product": "windows"},   # Indicator Removal

    # Credential Access
    "T1003":    {"category": "process_creation", "product": "windows"},   # Credential Dumping
    "T1056":    {"category": "process_creation", "product": "windows"},   # Input Capture

    # Collection
    "T1113":    {"category": "process_creation", "product": "windows"},   # Screen Capture
    "T1005":    {"category": "file_event",       "product": "windows"},   # Data from Local System
    "T1560":    {"category": "process_creation", "product": "windows"},   # Archive Collected Data

    # C2 — network-based
    "T1071":    {"category": "network_connection", "product": "windows"}, # App Layer Protocol
    "T1041":    {"category": "network_connection", "product": "windows"}, # Exfil over C2
    "T1567":    {"category": "network_connection", "product": "windows"}, # Exfil over Web
    "T1568":    {"category": "dns_query",          "product": "windows"}, # Dynamic Resolution
    "T1573":    {"category": "network_connection", "product": "windows"}, # Encrypted Channel
    "T1090":    {"category": "network_connection", "product": "windows"}, # Proxy
    "T1095":    {"category": "network_connection", "product": "windows"}, # Non-Application Layer
    "T1102":    {"category": "network_connection", "product": "windows"}, # Web Service

    # Impact
    "T1485":    {"category": "file_event",       "product": "windows"},   # Data Destruction
    "T1490":    {"category": "process_creation", "product": "windows"},   # Inhibit Recovery
    "T1489":    {"category": "process_creation", "product": "windows"},   # Service Stop
}

# Fallback when no TTP matches
_DEFAULT_SIGMA_LOGSOURCE: dict[str, str] = {
    "category": "network_connection",
    "product":  "windows",
}


def resolve_logsource(mitre_ttps: list[str]) -> dict[str, str]:
    """
    Pick the best Sigma logsource given a list of MITRE ATT&CK technique IDs.

    Strategy:
    1. Score each TTP against the map (longest prefix match wins for each TTP).
    2. Prefer process_creation > network_connection > file_event > others.
       (process_creation is most universally available and most detectable.)
    3. If nothing matches, return the network_connection fallback.

    Args:
        mitre_ttps: List of MITRE ATT&CK technique IDs from extracted intel.

    Returns:
        A Sigma logsource dict with at least 'category' and 'product' keys.
    """
    # Priority order for category selection
    category_priority = [
        "process_creation",
        "network_connection",
        "dns_query",
        "registry_event",
        "file_event",
        "image_load",
        "pipe_created",
    ]

    candidates: list[dict[str, str]] = []

    for ttp in (mitre_ttps or []):
        normalized = ttp.strip().upper()
        # Try exact match first, then parent technique (e.g. T1059.001 → T1059)
        match = _TTP_TO_SIGMA_LOGSOURCE.get(normalized)
        if not match:
            parent = normalized.split(".")[0]
            match = _TTP_TO_SIGMA_LOGSOURCE.get(parent)
        if match:
            candidates.append(match)

    if not candidates:
        return dict(_DEFAULT_SIGMA_LOGSOURCE)

    # Pick the highest-priority category found
    for preferred_cat in category_priority:
        for c in candidates:
            if c.get("category") == preferred_cat:
                return dict(c)

    return dict(candidates[0])


# ---------------------------------------------------------------------------
# TTP → Sentinel KQL table
# ---------------------------------------------------------------------------
# Two primary tables for the network vs. endpoint split:
#   SecurityEvent        — Windows endpoint events (process, logon, etc.)
#   CommonSecurityLog    — Network/firewall/proxy events (CEF format)
#
# We add DeviceNetworkEvents as a Defender XDR option for completeness,
# but Sentinel is the primary target (mirroring the design decision above).
# ---------------------------------------------------------------------------

_TTP_TO_KQL_TABLE: dict[str, str] = {
    # Process/endpoint techniques → SecurityEvent
    "T1059": "SecurityEvent",
    "T1047": "SecurityEvent",
    "T1053": "SecurityEvent",
    "T1055": "SecurityEvent",
    "T1036": "SecurityEvent",
    "T1027": "SecurityEvent",
    "T1003": "SecurityEvent",
    "T1056": "SecurityEvent",
    "T1547": "SecurityEvent",
    "T1543": "SecurityEvent",
    "T1218": "SecurityEvent",
    "T1070": "SecurityEvent",
    "T1113": "SecurityEvent",
    "T1490": "SecurityEvent",
    "T1485": "SecurityEvent",
    "T1489": "SecurityEvent",
    "T1566": "SecurityEvent",

    # Network/C2 techniques → CommonSecurityLog
    "T1071": "CommonSecurityLog",
    "T1041": "CommonSecurityLog",
    "T1567": "CommonSecurityLog",
    "T1568": "CommonSecurityLog",
    "T1573": "CommonSecurityLog",
    "T1090": "CommonSecurityLog",
    "T1095": "CommonSecurityLog",
    "T1102": "CommonSecurityLog",
}

_DEFAULT_KQL_TABLE = "CommonSecurityLog"


def resolve_kql_table(mitre_ttps: list[str]) -> str:
    """
    Pick the primary Sentinel KQL table given a list of MITRE ATT&CK technique IDs.

    Prefers SecurityEvent (endpoint) when endpoint TTPs are present.
    Falls back to CommonSecurityLog (network) for IOC-heavy rules.

    Args:
        mitre_ttps: List of MITRE ATT&CK technique IDs.

    Returns:
        The Sentinel table name as a string.
    """
    tables_seen: list[str] = []

    for ttp in (mitre_ttps or []):
        normalized = ttp.strip().upper()
        table = _TTP_TO_KQL_TABLE.get(normalized)
        if not table:
            parent = normalized.split(".")[0]
            table = _TTP_TO_KQL_TABLE.get(parent)
        if table and table not in tables_seen:
            tables_seen.append(table)

    # SecurityEvent preferred; if both are present, SecurityEvent wins
    if "SecurityEvent" in tables_seen:
        return "SecurityEvent"
    if tables_seen:
        return tables_seen[0]
    return _DEFAULT_KQL_TABLE


# ---------------------------------------------------------------------------
# Quick self-test (run: python src/ttp_logsource_map.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_cases = [
        ["T1059.001", "T1071.001"],          # PowerShell + C2 → process_creation
        ["T1071.004", "T1041"],              # DNS + exfil → network_connection
        ["T1547.001"],                       # Registry run key → registry_event
        ["T1566.001", "T1055", "T1071.001"],  # Phishing + injection + C2 → process_creation
        [],                                  # Empty → fallback network_connection
    ]
    for ttps in test_cases:
        ls = resolve_logsource(ttps)
        kql = resolve_kql_table(ttps)
        print(f"TTPs: {ttps or ['(none)']}")
        print(f"  Sigma logsource: {ls}")
        print(f"  KQL table:       {kql}")
        print()
