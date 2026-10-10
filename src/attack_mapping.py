import re

# Transparent candidate rules. A match is a hypothesis, not confirmation.
# More specific techniques are preferred where the log supports them.
RULES = [
    (r"powershell|encodedcommand", "T1059.001", "PowerShell",
     "PowerShell/encoded-command indicator; verify process command line and parent."),
    (r"cmd\.exe|bash\s+-c|wscript|cscript|script execution",
     "T1059", "Command and Scripting Interpreter",
     "Script or command execution indicator; confirm the interpreter and command."),
    (r"failed_login|login_failed|auth_failure|brute.force|repeated failed login",
     "T1110", "Brute Force",
     "Authentication-failure indicator; verify repeated attempts and source context."),
    (r"mimikatz|lsass|credential.dump|password.dump|dumpcred",
     "T1003", "OS Credential Dumping",
     "Credential-dumping indicator; confirm with endpoint evidence."),
    (r"archive_create|archive|compress|staging|7z|rar",
     "T1560", "Archive Collected Data",
     "Archive/staging indicator; confirm that data was collected for transfer."),
    (r"ransom|mass_file_encrypt|shadow_copy|vssadmin|file encryption|\.locked\b",
     "T1486", "Data Encrypted for Impact",
     "Encryption/ransomware-like indicator; verify file-operation evidence."),
    (r"webshell|unexpected upload|uploads/shell|php upload",
     "T1505.003", "Web Shell",
     "Possible web-shell indicator; verify uploaded file and execution evidence."),
    (r"large outbound|exfiltration|data exfil|outbound transfer",
     "T1041", "Exfiltration Over C2 Channel",
     "Possible transfer indicator; a network connection alone is insufficient evidence."),
    (r"remote service|psexec|winrm|wmic remote|remote execution|\bssh\b",
     "T1021", "Remote Services",
     "Remote-service indicator; confirm the service and remote execution context."),
]

def map_attack_techniques(df):
    """Return event-linked ATT&CK hypotheses; never aggregate evidence across all rows."""
    findings = []
    for _, row in df.iterrows():
        haystack = " ".join(str(row.get(k, "")) for k in
                            ("event_type", "details", "source_entity", "target_entity")).lower()
        seen = set()
        for pattern, tid, name, rationale in RULES:
            if re.search(pattern, haystack, flags=re.IGNORECASE) and tid not in seen:
                seen.add(tid)
                sub = tid.replace(".", "/")
                findings.append({
                    "event_id": str(row.get("event_id", "")),
                    "timestamp": str(row.get("timestamp", "")),
                    "source_entity": str(row.get("source_entity", "")),
                    "target_entity": str(row.get("target_entity", "")),
                    "technique_id": tid,
                    "technique": name,
                    "confidence": "candidate",
                    "evidence_rationale": rationale,
                    "evidence": str(row.get("details", ""))[:500],
                    "mitre_url": f"https://attack.mitre.org/techniques/{sub}/",
                })
    return findings
