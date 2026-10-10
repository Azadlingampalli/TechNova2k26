# RansomTrace AI Incident Report — enterprise_endpoint

## Summary
- Events analyzed: **1188**
- Events flagged: **8**
- Candidate paths: **1**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 1188,
  "ground_truth_attack_events": 8,
  "detected_events": 8,
  "true_positives": 8,
  "false_positives": 0,
  "false_negatives": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0,
  "attack_event_recall": 1.0,
  "original_nodes": 74,
  "reduced_nodes": 8,
  "node_reduction_pct": 89.19,
  "original_edges": 1188,
  "reduced_edges": 8,
  "edge_reduction_pct": 99.33,
  "attack_events_retained_in_reduced_graph": 8,
  "attack_event_retention_pct": 100.0,
  "retained_attack_event_ids": [
    "ENT-A-001",
    "ENT-A-002",
    "ENT-A-003",
    "ENT-A-004",
    "ENT-A-005",
    "ENT-A-006",
    "ENT-A-007",
    "ENT-A-008"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-001 (score 0.825)
- Time: 2026-10-01 10:00:00+00:00 — 2026-10-01 12:00:00+00:00
- Entities: cmd.exe_encoded, domain_admin, external_unknown_ip, finance_archive, finance_share, lsass_credentials, server_admin, unknown_ip_192.0.2.45
- Evidence:
  - `ENT-A-001` | 2026-10-01 10:00:00+00:00 | login_failed | `unknown_ip_192.0.2.45` → `server_admin` | score 0.91 | Authentication failures; Privilege-related activity; Unusual destination; Uncommon event type
  - `ENT-A-002` | 2026-10-01 10:12:00+00:00 | login_success | `unknown_ip_192.0.2.45` → `server_admin` | score 0.5800000000000001 | Privilege-related activity; Unusual destination
  - `ENT-A-003` | 2026-10-01 10:24:00+00:00 | process_start | `server_admin` → `cmd.exe_encoded` | score 0.5800000000000001 | Privilege-related activity; Script/command execution
  - `ENT-A-004` | 2026-10-01 10:36:00+00:00 | credential_access | `cmd.exe_encoded` → `lsass_credentials` | score 0.7299999999999999 | Script/command execution; Credential-access indicator; Uncommon event type
  - `ENT-A-005` | 2026-10-01 11:00:00+00:00 | privilege_change | `server_admin` → `domain_admin` | score 0.41000000000000003 | Privilege-related activity; Uncommon event type
  - `ENT-A-006` | 2026-10-01 11:12:00+00:00 | file_read | `domain_admin` → `finance_share` | score 0.5800000000000001 | Privilege-related activity; Sensitive data/staging indicator
  - `ENT-A-007` | 2026-10-01 11:30:00+00:00 | archive_create | `domain_admin` → `finance_archive` | score 0.66 | Privilege-related activity; Sensitive data/staging indicator; Uncommon event type
  - `ENT-A-008` | 2026-10-01 12:00:00+00:00 | network_connection | `finance_archive` → `external_unknown_ip` | score 0.55 | Sensitive data/staging indicator; Unusual destination

## Candidate MITRE ATT&CK mappings
- **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)** — event `ENT-A-001` at 2026-10-01 10:00:00+00:00: Authentication-failure indicator; verify repeated attempts and source context. Evidence: Multiple failed admin login attempts
- **[T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)** — event `ENT-A-003` at 2026-10-01 10:24:00+00:00: Script or command execution indicator; confirm the interpreter and command. Evidence: Encoded command interpreter launch
- **[T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)** — event `ENT-A-004` at 2026-10-01 10:36:00+00:00: Script or command execution indicator; confirm the interpreter and command. Evidence: Credential dumping indicator
- **[T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)** — event `ENT-A-004` at 2026-10-01 10:36:00+00:00: Credential-dumping indicator; confirm with endpoint evidence. Evidence: Credential dumping indicator
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `ENT-A-007` at 2026-10-01 11:30:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Archive of sensitive finance files
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `ENT-A-008` at 2026-10-01 12:00:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Unusual outbound network connection

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.