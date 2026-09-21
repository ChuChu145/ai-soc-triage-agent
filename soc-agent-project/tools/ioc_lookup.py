"""
IOC reputation lookup tool.

This is a STUB. It returns canned data for the indicators that appear in the
sample log so the agent has something real to reason over without needing
API keys yet. Swap the body of lookup_ioc() for real calls when you're ready
(see the TODO block below) — the function signature and return shape can
stay the same, so nothing else in the project needs to change.

Real services to wire in later:
  - VirusTotal API (https://developers.virustotal.com/reference) for
    IP / domain / file hash reputation.
  - AbuseIPDB API (https://docs.abuseipdb.com/) for IP abuse reports.
  - Both offer free tiers sufficient for portfolio/demo use.
"""

from __future__ import annotations

# Canned "known" indicators — mirrors what's in
# data/sample_logs/suspicious_login_lateral_movement.json
_STUB_DATA = {
    "185.220.101.47": {
        "indicator": "185.220.101.47",
        "type": "ip",
        "verdict": "malicious",
        "malicious_votes": 41,
        "harmless_votes": 2,
        "categories": ["tor exit node", "brute force source"],
        "notes": "Known Tor exit node range; frequently observed in RDP/SSH brute force campaigns.",
    },
    "45.153.240.18": {
        "indicator": "45.153.240.18",
        "type": "ip",
        "verdict": "suspicious",
        "malicious_votes": 17,
        "harmless_votes": 5,
        "categories": ["c2", "bulletproof hosting"],
        "notes": "Hosted on a provider commonly associated with C2 infrastructure; no legitimate business justification for traffic to this range from a finance workstation.",
    },
    "91B5F3A1C2E4D6789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567": {
        "indicator": "91B5F3A1C2E4D6789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "type": "file_hash",
        "verdict": "malicious",
        "malicious_votes": 52,
        "harmless_votes": 0,
        "categories": ["credential dumper", "lsass access tool"],
        "notes": "Hash matches a known LSASS credential dumping utility repackaged under a benign-looking filename.",
    },
}


def lookup_ioc(indicator: str, indicator_type: str) -> dict:
    """
    Look up reputation data for an IP address or file hash.

    Args:
        indicator: the IP address or hash string to check.
        indicator_type: one of "ip", "domain", "file_hash".

    Returns:
        A dict with verdict, vote counts, categories, and notes.
    """
    hit = _STUB_DATA.get(indicator)
    if hit:
        return hit

    # TODO: replace this fallback with a real API call, e.g.:
    #
    #   import requests
    #   resp = requests.get(
    #       f"https://www.virustotal.com/api/v3/{'ip_addresses' if indicator_type == 'ip' else 'files'}/{indicator}",
    #       headers={"x-apikey": os.environ["VT_API_KEY"]},
    #   )
    #   ...parse resp.json() into the same shape returned above...
    #
    return {
        "indicator": indicator,
        "type": indicator_type,
        "verdict": "unknown",
        "malicious_votes": 0,
        "harmless_votes": 0,
        "categories": [],
        "notes": "Not present in local stub dataset. Wire up a real lookup (VirusTotal/AbuseIPDB) in tools/ioc_lookup.py to get live data for indicators outside the sample log.",
    }
