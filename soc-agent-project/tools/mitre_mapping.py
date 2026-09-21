"""
MITRE ATT&CK technique mapping tool.

This is a STUB using a small local keyword -> technique table. It's enough
to cover the sample log and demonstrate the pattern. Swap for the real
ATT&CK dataset when you're ready (see TODO) — same function signature.

Real data source to wire in later:
  - MITRE's own STIX/TAXII feed (https://github.com/mitre/cti), or the
    `attackcti` Python package, which wraps it and lets you search techniques
    by keyword/tactic programmatically instead of hand-maintaining a table.
"""

from __future__ import annotations

_TECHNIQUE_TABLE = [
    {
        "keywords": ["brute force", "failed logon", "repeated failed", "password guessing"],
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["rdp", "remote desktop", "logon type 10"],
        "technique_id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
    },
    {
        "keywords": ["valid account", "successful logon", "legitimate credentials"],
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
    },
    {
        "keywords": ["lsass", "credential dump", "memory read of lsass"],
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["masquerad", "svhost", "svchost", "renamed binary", "lookalike filename"],
        "technique_id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
    },
    {
        "keywords": ["beacon", "c2", "outbound connection", "command and control", "port 443", "unusual outbound"],
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
    },
    {
        "keywords": ["scheduled task", "schtasks", "onlogon", "persistence"],
        "technique_id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution / Persistence / Privilege Escalation",
    },
]


def map_mitre_technique(behavior_description: str) -> list[dict]:
    """
    Map a plain-English description of observed behaviour to candidate
    MITRE ATT&CK techniques.

    Args:
        behavior_description: e.g. "repeated failed RDP logons from a single
            external IP followed by a success".

    Returns:
        A list of matching technique dicts (technique_id, name, tactic).
        Empty list if nothing matched locally.
    """
    text = behavior_description.lower()
    matches = []
    for row in _TECHNIQUE_TABLE:
        if any(kw in text for kw in row["keywords"]):
            matches.append(
                {
                    "technique_id": row["technique_id"],
                    "name": row["name"],
                    "tactic": row["tactic"],
                }
            )

    # TODO: replace/augment with a real lookup against MITRE's ATT&CK data,
    # e.g. using the `attackcti` package:
    #
    #   from attackcti import attack_client
    #   lift = attack_client()
    #   techniques = lift.get_techniques(stix_format=False)
    #   ...search `techniques` for behavior_description...
    #
    if not matches:
        return [
            {
                "technique_id": None,
                "name": None,
                "tactic": None,
                "notes": "No local keyword match. Expand tools/mitre_mapping.py's table or wire up the real ATT&CK dataset.",
            }
        ]
    return matches
