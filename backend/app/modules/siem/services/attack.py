"""MITRE ATT&CK technique dictionary (subset) and helpers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    name: str
    tactic: str


ATTACK_TECHNIQUES: dict[str, Technique] = {
    "T1059": Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1071": Technique("T1071", "Application Layer Protocol", "Command and Control"),
    "T1110": Technique("T1110", "Brute Force", "Credential Access"),
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1566": Technique("T1566", "Phishing", "Initial Access"),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "T1021": Technique("T1021", "Remote Services", "Lateral Movement"),
    "T1003": Technique("T1003", "OS Credential Dumping", "Credential Access"),
    "T1505": Technique("T1505", "Server Software Component (Web Shell)", "Persistence"),
    "T1046": Technique("T1046", "Network Service Discovery", "Discovery"),
    "T1547": Technique("T1547", "Boot or Logon Autostart Execution", "Persistence"),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "Impact"),
    "T1078": Technique("T1078", "Valid Accounts", "Defense Evasion"),
    "T1210": Technique("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "T1560": Technique("T1560", "Archive Collected Data", "Collection"),
    "T1098": Technique("T1098", "Account Manipulation", "Persistence"),
    "T1070": Technique("T1070", "Indicator Removal", "Defense Evasion"),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1572": Technique("T1572", "Protocol Tunneling", "Command and Control"),
    "T1136": Technique("T1136", "Create Account", "Persistence"),
}


def lookup(technique_id: str) -> Technique | None:
    return ATTACK_TECHNIQUES.get(technique_id.upper())


def map_ids(technique_ids: list[str]) -> list[Technique]:
    out: list[Technique] = []
    for tid in technique_ids:
        t = lookup(tid)
        if t is not None:
            out.append(t)
    return out


def tactics_for(technique_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    tactics: list[str] = []
    for t in map_ids(technique_ids):
        if t.tactic not in seen:
            seen.add(t.tactic)
            tactics.append(t.tactic)
    return tactics
