# RansomTrace AI Incident Report — college_website

## Summary
- Events analyzed: **1187**
- Events flagged: **7**
- Candidate paths: **3**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 1187,
  "ground_truth_attack_events": 7,
  "detected_events": 7,
  "true_positives": 7,
  "false_positives": 0,
  "false_negatives": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0,
  "attack_event_recall": 1.0,
  "original_nodes": 73,
  "reduced_nodes": 30,
  "node_reduction_pct": 58.9,
  "original_edges": 1187,
  "reduced_edges": 392,
  "edge_reduction_pct": 66.98,
  "attack_events_retained_in_reduced_graph": 7,
  "attack_event_retention_pct": 100.0,
  "retained_attack_event_ids": [
    "COL-A-001",
    "COL-A-002",
    "COL-A-003",
    "COL-A-004",
    "COL-A-005",
    "COL-A-006",
    "COL-A-007"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-003 (score 0.722)
- Time: 2026-10-01 07:12:00+00:00 — 2026-10-01 08:24:00+00:00
- Entities: external_unknown_ip, php_webshell, service_admin, student_records, student_records_archive, web_server
- Evidence:
  - `COL-A-003` | 2026-10-01 07:12:00+00:00 | process_start | `web_server` → `php_webshell` | score 0.33 | Suspicious web activity
  - `COL-A-004` | 2026-10-01 07:30:00+00:00 | database_query | `php_webshell` → `student_records` | score 0.66 | Sensitive data/staging indicator; Suspicious web activity; Uncommon event type
  - `COL-A-005` | 2026-10-01 08:00:00+00:00 | archive_create | `php_webshell` → `student_records_archive` | score 0.66 | Sensitive data/staging indicator; Suspicious web activity; Uncommon event type
  - `COL-A-006` | 2026-10-01 08:12:00+00:00 | network_connection | `student_records_archive` → `external_unknown_ip` | score 0.55 | Sensitive data/staging indicator; Unusual destination
  - `COL-A-007` | 2026-10-01 08:24:00+00:00 | privilege_change | `web_server` → `service_admin` | score 0.41000000000000003 | Privilege-related activity; Uncommon event type
### path-001 (score 0.62)
- Time: 2026-10-01 07:00:00+00:00 — 2026-10-01 07:00:00+00:00
- Entities: college_portal, unknown_ip_198.51.100.24
- Evidence:
  - `COL-A-001` | 2026-10-01 07:00:00+00:00 | http_request | `unknown_ip_198.51.100.24` → `college_portal` | score 0.5800000000000001 | Unusual destination; Suspicious web activity
### path-002 (score 0.37)
- Time: 2026-10-01 07:06:00+00:00 — 2026-10-01 07:06:00+00:00
- Entities: /uploads/unexpected.php, web_app
- Evidence:
  - `COL-A-002` | 2026-10-01 07:06:00+00:00 | file_write | `web_app` → `/uploads/unexpected.php` | score 0.33 | Suspicious web activity

## Candidate MITRE ATT&CK mappings
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `COL-A-003` at 2026-10-01 07:12:00+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: Possible web shell process
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `COL-A-004` at 2026-10-01 07:30:00+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: Sensitive student records query
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `COL-A-005` at 2026-10-01 08:00:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Student record staging archive
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `COL-A-005` at 2026-10-01 08:00:00+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: Student record staging archive
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `COL-A-006` at 2026-10-01 08:12:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Unusual outbound connection

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.