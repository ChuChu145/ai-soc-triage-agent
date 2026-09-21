"""
Claude tool schemas + dispatch table, in one place so agent.py doesn't need
to know the details of each tool's implementation.
"""

from tools.ioc_lookup import lookup_ioc
from tools.mitre_mapping import map_mitre_technique

TOOLS = [
    {
        "name": "lookup_ioc",
        "description": (
            "Look up reputation data for an indicator of compromise (an IP "
            "address or file hash) seen in the logs. Use this before deciding "
            "how much weight to give any IP or hash in your analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The IP address or file hash to look up.",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "file_hash"],
                    "description": "The type of indicator being looked up.",
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    },
    {
        "name": "map_mitre_technique",
        "description": (
            "Map a plain-English description of observed behaviour to "
            "candidate MITRE ATT&CK technique IDs and names. Use this instead "
            "of guessing technique IDs from memory."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "behavior_description": {
                    "type": "string",
                    "description": (
                        "Plain-English description of the behaviour to map, "
                        "e.g. 'repeated failed RDP logons from one external IP "
                        "followed by a success'."
                    ),
                },
            },
            "required": ["behavior_description"],
        },
    },
]

# Maps tool name -> callable. agent.py uses this to dispatch tool_use blocks
# without a big if/elif chain.
DISPATCH = {
    "lookup_ioc": lambda inp: lookup_ioc(inp["indicator"], inp["indicator_type"]),
    "map_mitre_technique": lambda inp: map_mitre_technique(inp["behavior_description"]),
}
