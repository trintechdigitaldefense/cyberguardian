"""Structured response playbooks — human-gated destructive steps when Client Mode is on."""
from typing import Dict, Any, List

PLAYBOOKS = {
    "credential_theft": {
        "id": "credential_theft",
        "name": "Credential Theft / Dumping",
        "match_tags": ["credential_access", "mimikatz", "hashdump", "sekurlsa"],
        "match_title": ["mimikatz", "credential", "lsass", "hashdump", "sekurlsa"],
        "steps": [
            {"step": 1, "action": "alert_only", "auto": True, "desc": "Raise high-priority alert"},
            {"step": 2, "action": "kill_process", "auto": True, "desc": "Terminate dumping tool if PID known"},
            {"step": 3, "action": "isolate_host", "auto": True, "desc": "Network-isolate host"},
            {"step": 4, "action": "escalate", "auto": False, "desc": "Human: force password resets"},
        ],
        "analyst_notes": "Verify authorized pentest. Rotate credentials if malicious.",
    },
    "ransomware": {
        "id": "ransomware",
        "name": "Ransomware / Destructive Prep",
        "match_tags": ["ransomware", "impact", "encrypt"],
        "match_title": ["ransomware", "encrypt", ".locked", "vssadmin"],
        "steps": [
            {"step": 1, "action": "alert_only", "auto": True, "desc": "Critical alert"},
            {"step": 2, "action": "isolate_host", "auto": True, "desc": "Isolate immediately"},
            {"step": 3, "action": "kill_process", "auto": True, "desc": "Stop encryption process if identified"},
            {"step": 4, "action": "escalate", "auto": False, "desc": "Human: verify backups, preserve evidence"},
        ],
        "analyst_notes": "Check backup integrity. Do not pay. Preserve logs.",
    },
    "c2_beacon": {
        "id": "c2_beacon",
        "name": "C2 / Beacon Pattern",
        "match_tags": ["c2", "beacon"],
        "match_title": ["beacon", "c2", "periodic outbound"],
        "steps": [
            {"step": 1, "action": "alert_only", "auto": True, "desc": "Alert on C2 pattern"},
            {"step": 2, "action": "block_ip", "auto": True, "desc": "Block destination if known"},
            {"step": 3, "action": "isolate_host", "auto": True, "desc": "Isolate host"},
            {"step": 4, "action": "escalate", "auto": False, "desc": "Human: scope lateral movement"},
        ],
        "analyst_notes": "Confirm not legitimate monitoring software.",
    },
}


def match_playbook(title: str, tags: List[str]) -> Dict[str, Any] | None:
    title_l = (title or "").lower()
    tagset = {str(t).lower() for t in (tags or [])}
    for pb in PLAYBOOKS.values():
        if any(t in tagset for t in pb["match_tags"]):
            return pb
        if any(m in title_l for m in pb["match_title"]):
            return pb
    return None
