# RansomTrace AI Incident Report — company

## Summary
- Events analyzed: **1189**
- Events flagged: **9**
- Candidate paths: **1**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 1189,
  "ground_truth_attack_events": 9,
  "detected_events": 9,
  "true_positives": 9,
  "false_positives": 0,
  "false_negatives": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0,
  "attack_event_recall": 1.0,
  "original_nodes": 74,
  "reduced_nodes": 11,
  "node_reduction_pct": 85.14,
  "original_edges": 1189,
  "reduced_edges": 24,
  "edge_reduction_pct": 97.98,
  "attack_events_retained_in_reduced_graph": 9,
  "attack_event_retention_pct": 100.0,
  "retained_attack_event_ids": [
    "COM-A-001",
    "COM-A-002",
    "COM-A-003",
    "COM-A-004",
    "COM-A-005",
    "COM-A-006",
    "COM-A-007",
    "COM-A-008",
    "COM-A-009"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-001 (score 0.739)
- Time: 2026-10-01 03:00:00+00:00 — 2026-10-01 05:18:00+00:00
- Entities: admin_role, customer_db, customer_db_archive, employee_7, external_unknown_ip, powershell_encoded, shadow_copy_delete.log, shared_drive, unknown_ip_203.0.113.77
- Evidence:
  - `COM-A-001` | 2026-10-01 03:00:00+00:00 | login_failed | `unknown_ip_203.0.113.77` → `employee_7` | score 0.63 | Authentication failures; Unusual destination; Uncommon event type
  - `COM-A-002` | 2026-10-01 03:12:00+00:00 | login_success | `unknown_ip_203.0.113.77` → `employee_7` | score 0.3 | Unusual destination
  - `COM-A-003` | 2026-10-01 03:30:00+00:00 | privilege_change | `employee_7` → `admin_role` | score 0.41000000000000003 | Privilege-related activity; Uncommon event type
  - `COM-A-004` | 2026-10-01 04:00:00+00:00 | process_start | `employee_7` → `powershell_encoded` | score 0.3 | Script/command execution
  - `COM-A-005` | 2026-10-01 04:12:00+00:00 | file_read | `powershell_encoded` → `customer_db` | score 0.55 | Script/command execution; Sensitive data/staging indicator
  - `COM-A-006` | 2026-10-01 04:30:00+00:00 | archive_create | `powershell_encoded` → `customer_db_archive` | score 0.63 | Script/command execution; Sensitive data/staging indicator; Uncommon event type
  - `COM-A-007` | 2026-10-01 05:00:00+00:00 | network_connection | `customer_db_archive` → `external_unknown_ip` | score 0.55 | Sensitive data/staging indicator; Unusual destination
  - `COM-A-008` | 2026-10-01 05:06:00+00:00 | file_write | `powershell_encoded` → `shadow_copy_delete.log` | score 0.7 | Script/command execution; Possible ransomware behavior
  - `COM-A-009` | 2026-10-01 05:18:00+00:00 | mass_file_encrypt | `powershell_encoded` → `shared_drive` | score 0.7799999999999999 | Script/command execution; Possible ransomware behavior; Uncommon event type

## Candidate MITRE ATT&CK mappings
- **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)** — event `COM-A-001` at 2026-10-01 03:00:00+00:00: Authentication-failure indicator; verify repeated attempts and source context. Evidence: Repeated failed login attempts
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `COM-A-004` at 2026-10-01 04:00:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Encoded PowerShell command observed
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `COM-A-005` at 2026-10-01 04:12:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Sensitive customer database accessed
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `COM-A-006` at 2026-10-01 04:30:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Sensitive data staging archive
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `COM-A-006` at 2026-10-01 04:30:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Sensitive data staging archive
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `COM-A-007` at 2026-10-01 05:00:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Unusual external connection after staging
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `COM-A-008` at 2026-10-01 05:06:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Shadow-copy deletion indicator
- **[T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)** — event `COM-A-008` at 2026-10-01 05:06:00+00:00: Encryption/ransomware-like indicator; verify file-operation evidence. Evidence: Shadow-copy deletion indicator
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `COM-A-009` at 2026-10-01 05:18:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Mass file encryption behavior
- **[T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)** — event `COM-A-009` at 2026-10-01 05:18:00+00:00: Encryption/ransomware-like indicator; verify file-operation evidence. Evidence: Mass file encryption behavior

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.