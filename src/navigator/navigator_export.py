"""
src/navigator/navigator_export.py — MITRE ATT&CK Navigator layer generator.

Builds a Navigator v4.9 layer JSON from a list of MITRE ATT&CK technique IDs.
The layer can be loaded directly at navigator.attack.mitre.org.

Usage:
    from src.navigator import build_navigator_layer

    layer = build_navigator_layer(
        ttps=["T1059.001", "T1071.001", "T1041"],
        name="APT41 Campaign Layer",
        description="Techniques observed in APT41 telecom campaign",
    )
    # Returns a dict ready to serialize as JSON

    # Or from multiple reports:
    layer = ttps_to_navigator_layer([
        {"threat_actor": "APT41", "ttps": ["T1059.001", "T1071"]},
        {"threat_actor": "Sandworm", "ttps": ["T1485", "T1490", "T1059"]},
    ])
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from typing import Optional

# ---------------------------------------------------------------------------
# ATT&CK Navigator layer schema version
# ---------------------------------------------------------------------------
_NAVIGATOR_VERSION = "4.9"
_LAYER_VERSION = "4.5"
_ATTACK_VERSION = "15"
_DOMAIN = "enterprise-attack"

# ---------------------------------------------------------------------------
# Tactic lookup — TTP prefix → tactic shortname (used for Navigator metadata)
# ---------------------------------------------------------------------------
_TTP_TO_TACTIC: dict[str, str] = {
    # Initial Access
    "T1566": "initial-access",
    "T1078": "initial-access",
    "T1190": "initial-access",
    "T1133": "initial-access",

    # Execution
    "T1059": "execution",
    "T1047": "execution",
    "T1053": "execution",
    "T1204": "execution",
    "T1569": "execution",

    # Persistence
    "T1547": "persistence",
    "T1543": "persistence",
    "T1037": "persistence",
    "T1505": "persistence",

    # Privilege Escalation
    "T1055": "privilege-escalation",
    "T1134": "privilege-escalation",
    "T1068": "privilege-escalation",

    # Defense Evasion
    "T1036": "defense-evasion",
    "T1027": "defense-evasion",
    "T1218": "defense-evasion",
    "T1070": "defense-evasion",
    "T1140": "defense-evasion",
    "T1132": "defense-evasion",

    # Credential Access
    "T1003": "credential-access",
    "T1056": "credential-access",

    # Discovery
    "T1082": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1069": "discovery",
    "T1135": "discovery",

    # Lateral Movement
    "T1021": "lateral-movement",
    "T1550": "lateral-movement",

    # Collection
    "T1113": "collection",
    "T1005": "collection",
    "T1560": "collection",
    "T1115": "collection",

    # Command & Control
    "T1071": "command-and-control",
    "T1041": "command-and-control",
    "T1567": "exfiltration",
    "T1568": "command-and-control",
    "T1573": "command-and-control",
    "T1090": "command-and-control",
    "T1095": "command-and-control",
    "T1102": "command-and-control",

    # Exfiltration
    "T1048": "exfiltration",
    "T1537": "exfiltration",

    # Impact
    "T1485": "impact",
    "T1490": "impact",
    "T1489": "impact",
    "T1498": "impact",
    "T1499": "impact",
}


def _normalize_ttp(ttp: str) -> str:
    """Normalize a TTP string to uppercase (e.g., 't1059.001' → 'T1059.001')."""
    return ttp.strip().upper()


def _get_tactic(ttp: str) -> Optional[str]:
    """Return the tactic shortname for a TTP, or None if unknown."""
    normalized = _normalize_ttp(ttp)
    tactic = _TTP_TO_TACTIC.get(normalized)
    if not tactic:
        parent = normalized.split(".")[0]
        tactic = _TTP_TO_TACTIC.get(parent)
    return tactic


def _score_to_color(score: int, max_score: int) -> str:
    """
    Map a frequency score to a hex color on a white→red gradient.

    Frequency 1 → light red (#ffb3b3)
    Frequency max → deep red (#cc0000)

    Returns an HTML hex color string.
    """
    if max_score <= 1:
        return "#ff6666"
    ratio = (score - 1) / (max_score - 1)  # 0.0 at min, 1.0 at max
    # Interpolate between #ffb3b3 (light) and #cc0000 (deep)
    r_start, g_start, b_start = 0xff, 0xb3, 0xb3
    r_end,   g_end,   b_end   = 0xcc, 0x00, 0x00
    r = int(r_start + (r_end - r_start) * ratio)
    g = int(g_start + (g_end - g_start) * ratio)
    b = int(b_start + (b_end - b_start) * ratio)
    return f"#{r:02x}{g:02x}{b:02x}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_navigator_layer(
    ttps: list[str],
    name: str = "Agentic-CTI Threat Landscape",
    description: str = "Automatically generated ATT&CK layer from Agentic-CTI pipeline.",
    *,
    max_gradient: int = 10,
) -> dict:
    """
    Build a MITRE ATT&CK Navigator layer dict from a flat list of TTP IDs.

    Each unique TTP gets a score = its frequency in the list, with color
    intensity proportional to frequency (higher frequency = darker red).

    Args:
        ttps:         List of MITRE ATT&CK technique IDs (may contain duplicates
                      from multiple reports).
        name:         Layer name shown in Navigator.
        description:  Layer description shown in Navigator.
        max_gradient: Maximum score value for the color gradient scale.

    Returns:
        A dict conforming to the ATT&CK Navigator v4.9 layer schema.
    """
    # Normalize and count
    normalized = [_normalize_ttp(t) for t in ttps if t and t.strip()]
    counts = Counter(normalized)

    if not counts:
        max_score = 1
    else:
        max_score = max(counts.values())

    techniques = []
    unmapped_ttps: list[str] = []

    for ttp_id, score in sorted(counts.items(), key=lambda x: -x[1]):
        tactic = _get_tactic(ttp_id)
        if not tactic:
            unmapped_ttps.append(ttp_id)
            logger.warning(
                "Navigator: TTP '%s' has no tactic mapping -- included in layer without tactic field. "
                "Add it to _TTP_TO_TACTIC in navigator_export.py to fix this.",
                ttp_id,
            )
        color = _score_to_color(score, max_score)
        entry: dict = {
            "techniqueID": ttp_id,
            "score": score,
            "color": color,
            "comment": f"Observed {score} time{'s' if score > 1 else ''} across analyzed reports",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": "." in ttp_id,
        }
        if tactic:
            entry["tactic"] = tactic
        techniques.append(entry)

    gradient_max = max(max_gradient, max_score)

    return {
        "name": name,
        "versions": {
            "attack":    _ATTACK_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer":     _LAYER_VERSION,
        },
        "domain": _DOMAIN,
        "description": description,
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS",
                "Network", "IaaS", "SaaS", "Office 365",
                "Azure AD", "Google Workspace",
            ],
        },
        "sorting": 3,  # sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666", "#cc0000"],
            "minValue": 0,
            "maxValue": gradient_max,
        },
        "legendItems": [],
        "metadata": [
            {
                "name": "generated_by",
                "value": "Agentic-CTI",
            },
            {
                "name": "total_techniques",
                "value": str(len(techniques)),
            },
            {
                "name": "layer_id",
                "value": str(uuid.uuid4()),
            },
            *(
                [{"name": "unmapped_ttps", "value": ", ".join(unmapped_ttps)}]
                if unmapped_ttps else []
            ),
        ],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0a1628",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }


def ttps_to_navigator_layer(
    reports: list[dict],
    name: str = "Agentic-CTI Threat Landscape",
    description: str = "Automatically generated ATT&CK layer from Agentic-CTI pipeline.",
) -> dict:
    """
    Build a Navigator layer from a list of report dicts.

    Each report dict must have a 'ttps' key (list of TTP strings).
    Optionally, may include 'threat_actor' for the description.

    Args:
        reports:     List of dicts, each with at minimum {'ttps': [...]}.
        name:        Layer name.
        description: Layer description.

    Returns:
        ATT&CK Navigator layer dict.
    """
    all_ttps: list[str] = []
    actors_seen: list[str] = []

    for r in reports:
        ttps_list = r.get("ttps") or r.get("mitre_ttps") or []
        all_ttps.extend(ttps_list)
        actor = r.get("threat_actor") or r.get("actor")
        if actor and actor not in actors_seen:
            actors_seen.append(actor)

    if actors_seen:
        description = (
            f"TTPs extracted from {len(reports)} report(s) for: "
            + ", ".join(actors_seen[:5])
            + (f" (+{len(actors_seen)-5} more)" if len(actors_seen) > 5 else "")
            + ". Generated by Agentic-CTI."
        )

    return build_navigator_layer(all_ttps, name=name, description=description)


# ---------------------------------------------------------------------------
# Quick self-test (run: python src/navigator/navigator_export.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    layer = build_navigator_layer(
        ttps=[
            "T1059.001", "T1059.001", "T1059.005",  # PowerShell frequent
            "T1071.001", "T1071.004",
            "T1041", "T1041",
            "T1078", "T1566.001", "T1566.002",
            "T1036", "T1027", "T1003.001",
            "T1113", "T1115", "T1485", "T1490",
        ],
        name="Test Layer",
        description="Self-test",
    )

    print(f"Generated Navigator layer with {len(layer['techniques'])} techniques")
    print(f"Top techniques by score:")
    for t in sorted(layer["techniques"], key=lambda x: -x["score"])[:5]:
        print(f"  {t['techniqueID']}: score={t['score']}  color={t['color']}  tactic={t.get('tactic', 'N/A')}")

    # Validate required schema fields
    required = ["name", "versions", "domain", "techniques", "gradient"]
    for field in required:
        assert field in layer, f"Missing required field: {field}"
    print(f"\nSchema validation: PASS (all required fields present)")
