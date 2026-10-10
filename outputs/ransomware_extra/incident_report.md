# RansomTrace AI Incident Report — ransomware_extra

## Summary
- Events analyzed: **729**
- Events flagged: **97**
- Candidate paths: **84**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 729,
  "ground_truth_attack_events": 9,
  "detected_events": 97,
  "true_positives": 8,
  "false_positives": 89,
  "false_negatives": 1,
  "precision": 0.0825,
  "recall": 0.8889,
  "f1": 0.1509,
  "attack_event_recall": 0.8889,
  "original_nodes": 283,
  "reduced_nodes": 51,
  "node_reduction_pct": 81.98,
  "original_edges": 729,
  "reduced_edges": 97,
  "edge_reduction_pct": 86.69,
  "attack_events_retained_in_reduced_graph": 8,
  "attack_event_retention_pct": 88.89,
  "retained_attack_event_ids": [
    "RAN-A-002",
    "RAN-A-003",
    "RAN-A-004",
    "RAN-A-005",
    "RAN-A-006",
    "RAN-A-007",
    "RAN-A-008",
    "RAN-A-009"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-036 (score 0.675)
- Time: 2026-09-23 04:00:35+00:00 — 2026-09-23 04:07:00+00:00
- Entities: archive_staging.zip, corp-fs-01, credential_dump.dat, encryptor.exe, finance_share, invoice.doc, powershell.exe, shadow_copy, unknown_ip_198.51.100.42
- Evidence:
  - `RAN-A-002` | 2026-09-23 04:00:35+00:00 | process_start | `invoice.doc` → `powershell.exe` | score 0.3 | Script/command execution
  - `RAN-A-003` | 2026-09-23 04:01:10+00:00 | file_write | `powershell.exe` → `credential_dump.dat` | score 0.6499999999999999 | Script/command execution; Credential-access indicator
  - `RAN-A-004` | 2026-09-23 04:01:45+00:00 | network_connection | `powershell.exe` → `unknown_ip_198.51.100.42` | score 0.55 | Script/command execution; Unusual destination
  - `RAN-A-005` | 2026-09-23 04:02:40+00:00 | file_read | `powershell.exe` → `finance_share` | score 0.55 | Script/command execution; Sensitive data/staging indicator
  - `RAN-A-006` | 2026-09-23 04:03:40+00:00 | file_write | `powershell.exe` → `archive_staging.zip` | score 0.55 | Script/command execution; Sensitive data/staging indicator
  - `RAN-A-007` | 2026-09-23 04:04:50+00:00 | network_connection | `powershell.exe` → `corp-fs-01` | score 0.3 | Script/command execution
  - `RAN-A-008` | 2026-09-23 04:06:00+00:00 | file_write | `encryptor.exe` → `finance_share` | score 0.45 | Possible ransomware behavior
  - `RAN-A-009` | 2026-09-23 04:07:00+00:00 | process_start | `encryptor.exe` → `shadow_copy` | score 0.45 | Possible ransomware behavior
### path-014 (score 0.41)
- Time: 2026-09-21 00:48:55+00:00 — 2026-09-21 03:10:14+00:00
- Entities: endpoint_agent_10, security_console16, security_console18
- Evidence:
  - `RAN-N-00666` | 2026-09-21 00:48:55+00:00 | network_connection | `endpoint_agent_10` → `security_console18` | score 0.33 | Suspicious web activity
  - `RAN-N-00104` | 2026-09-21 03:10:14+00:00 | network_connection | `endpoint_agent_10` → `security_console16` | score 0.33 | Suspicious web activity
### path-035 (score 0.41)
- Time: 2026-09-23 03:22:42+00:00 — 2026-09-23 03:24:17+00:00
- Entities: endpoint_agent_11, endpoint_agent_16, security_console7
- Evidence:
  - `RAN-N-00453` | 2026-09-23 03:22:42+00:00 | network_connection | `endpoint_agent_16` → `security_console7` | score 0.33 | Suspicious web activity
  - `RAN-N-00385` | 2026-09-23 03:24:17+00:00 | network_connection | `endpoint_agent_11` → `security_console7` | score 0.33 | Suspicious web activity
### path-040 (score 0.41)
- Time: 2026-09-23 13:43:23+00:00 — 2026-09-23 14:52:38+00:00
- Entities: endpoint_agent_20, endpoint_agent_4, security_console14
- Evidence:
  - `RAN-N-00144` | 2026-09-23 13:43:23+00:00 | network_connection | `endpoint_agent_4` → `security_console14` | score 0.33 | Suspicious web activity
  - `RAN-N-00370` | 2026-09-23 14:52:38+00:00 | network_connection | `endpoint_agent_20` → `security_console14` | score 0.33 | Suspicious web activity
### path-042 (score 0.41)
- Time: 2026-09-23 20:18:13+00:00 — 2026-09-23 22:21:23+00:00
- Entities: endpoint_agent_2, security_console15, security_console18
- Evidence:
  - `RAN-N-00519` | 2026-09-23 20:18:13+00:00 | network_connection | `endpoint_agent_2` → `security_console18` | score 0.33 | Suspicious web activity
  - `RAN-N-00455` | 2026-09-23 22:21:23+00:00 | network_connection | `endpoint_agent_2` → `security_console15` | score 0.33 | Suspicious web activity
### path-043 (score 0.41)
- Time: 2026-09-23 22:52:56+00:00 — 2026-09-24 03:12:43+00:00
- Entities: endpoint_agent_14, endpoint_agent_9, security_console2
- Evidence:
  - `RAN-N-00067` | 2026-09-23 22:52:56+00:00 | network_connection | `endpoint_agent_14` → `security_console2` | score 0.33 | Suspicious web activity
  - `RAN-N-00338` | 2026-09-24 03:12:43+00:00 | network_connection | `endpoint_agent_9` → `security_console2` | score 0.33 | Suspicious web activity
### path-079 (score 0.41)
- Time: 2026-09-26 11:51:19+00:00 — 2026-09-26 11:52:13+00:00
- Entities: endpoint_agent_11, endpoint_agent_20, security_console17
- Evidence:
  - `RAN-N-00707` | 2026-09-26 11:51:19+00:00 | network_connection | `endpoint_agent_20` → `security_console17` | score 0.33 | Suspicious web activity
  - `RAN-N-00352` | 2026-09-26 11:52:13+00:00 | network_connection | `endpoint_agent_11` → `security_console17` | score 0.33 | Suspicious web activity
### path-001 (score 0.37)
- Time: 2026-09-20 01:02:23+00:00 — 2026-09-20 01:02:23+00:00
- Entities: endpoint_agent_22, security_console15
- Evidence:
  - `RAN-N-00714` | 2026-09-20 01:02:23+00:00 | network_connection | `endpoint_agent_22` → `security_console15` | score 0.33 | Suspicious web activity
### path-002 (score 0.37)
- Time: 2026-09-20 01:46:57+00:00 — 2026-09-20 01:46:57+00:00
- Entities: endpoint_agent_14, security_console2
- Evidence:
  - `RAN-N-00175` | 2026-09-20 01:46:57+00:00 | network_connection | `endpoint_agent_14` → `security_console2` | score 0.33 | Suspicious web activity
### path-003 (score 0.37)
- Time: 2026-09-20 02:50:25+00:00 — 2026-09-20 02:50:25+00:00
- Entities: endpoint_agent_1, security_console12
- Evidence:
  - `RAN-N-00422` | 2026-09-20 02:50:25+00:00 | network_connection | `endpoint_agent_1` → `security_console12` | score 0.33 | Suspicious web activity
### path-004 (score 0.37)
- Time: 2026-09-20 11:29:32+00:00 — 2026-09-20 11:29:32+00:00
- Entities: endpoint_agent_14, security_console8
- Evidence:
  - `RAN-N-00360` | 2026-09-20 11:29:32+00:00 | network_connection | `endpoint_agent_14` → `security_console8` | score 0.33 | Suspicious web activity
### path-005 (score 0.37)
- Time: 2026-09-20 12:21:52+00:00 — 2026-09-20 12:21:52+00:00
- Entities: endpoint_agent_25, security_console6
- Evidence:
  - `RAN-N-00353` | 2026-09-20 12:21:52+00:00 | network_connection | `endpoint_agent_25` → `security_console6` | score 0.33 | Suspicious web activity
### path-006 (score 0.37)
- Time: 2026-09-20 12:35:22+00:00 — 2026-09-20 12:35:22+00:00
- Entities: endpoint_agent_6, security_console17
- Evidence:
  - `RAN-N-00235` | 2026-09-20 12:35:22+00:00 | network_connection | `endpoint_agent_6` → `security_console17` | score 0.33 | Suspicious web activity
### path-007 (score 0.37)
- Time: 2026-09-20 13:21:07+00:00 — 2026-09-20 13:21:07+00:00
- Entities: endpoint_agent_22, security_console18
- Evidence:
  - `RAN-N-00364` | 2026-09-20 13:21:07+00:00 | network_connection | `endpoint_agent_22` → `security_console18` | score 0.33 | Suspicious web activity
### path-008 (score 0.37)
- Time: 2026-09-20 16:14:06+00:00 — 2026-09-20 16:14:06+00:00
- Entities: endpoint_agent_13, security_console5
- Evidence:
  - `RAN-N-00070` | 2026-09-20 16:14:06+00:00 | network_connection | `endpoint_agent_13` → `security_console5` | score 0.33 | Suspicious web activity
### path-009 (score 0.37)
- Time: 2026-09-20 18:33:32+00:00 — 2026-09-20 18:33:32+00:00
- Entities: endpoint_agent_20, security_console3
- Evidence:
  - `RAN-N-00511` | 2026-09-20 18:33:32+00:00 | network_connection | `endpoint_agent_20` → `security_console3` | score 0.33 | Suspicious web activity
### path-010 (score 0.37)
- Time: 2026-09-20 21:13:38+00:00 — 2026-09-20 21:13:38+00:00
- Entities: endpoint_agent_12, security_console17
- Evidence:
  - `RAN-N-00257` | 2026-09-20 21:13:38+00:00 | network_connection | `endpoint_agent_12` → `security_console17` | score 0.33 | Suspicious web activity
### path-011 (score 0.37)
- Time: 2026-09-20 22:59:25+00:00 — 2026-09-20 22:59:25+00:00
- Entities: endpoint_agent_15, security_console12
- Evidence:
  - `RAN-N-00090` | 2026-09-20 22:59:25+00:00 | network_connection | `endpoint_agent_15` → `security_console12` | score 0.33 | Suspicious web activity
### path-012 (score 0.37)
- Time: 2026-09-21 00:25:34+00:00 — 2026-09-21 00:25:34+00:00
- Entities: endpoint_agent_16, security_console14
- Evidence:
  - `RAN-N-00245` | 2026-09-21 00:25:34+00:00 | network_connection | `endpoint_agent_16` → `security_console14` | score 0.33 | Suspicious web activity
### path-013 (score 0.37)
- Time: 2026-09-21 00:42:24+00:00 — 2026-09-21 00:42:24+00:00
- Entities: endpoint_agent_6, security_console15
- Evidence:
  - `RAN-N-00209` | 2026-09-21 00:42:24+00:00 | network_connection | `endpoint_agent_6` → `security_console15` | score 0.33 | Suspicious web activity
### path-015 (score 0.37)
- Time: 2026-09-21 04:32:35+00:00 — 2026-09-21 04:32:35+00:00
- Entities: endpoint_agent_11, security_console11
- Evidence:
  - `RAN-N-00398` | 2026-09-21 04:32:35+00:00 | network_connection | `endpoint_agent_11` → `security_console11` | score 0.33 | Suspicious web activity
### path-016 (score 0.37)
- Time: 2026-09-21 04:55:56+00:00 — 2026-09-21 04:55:56+00:00
- Entities: endpoint_agent_9, security_console5
- Evidence:
  - `RAN-N-00237` | 2026-09-21 04:55:56+00:00 | network_connection | `endpoint_agent_9` → `security_console5` | score 0.33 | Suspicious web activity
### path-017 (score 0.37)
- Time: 2026-09-21 05:54:55+00:00 — 2026-09-21 05:54:55+00:00
- Entities: endpoint_agent_10, security_console11
- Evidence:
  - `RAN-N-00200` | 2026-09-21 05:54:55+00:00 | network_connection | `endpoint_agent_10` → `security_console11` | score 0.33 | Suspicious web activity
### path-018 (score 0.37)
- Time: 2026-09-21 05:55:12+00:00 — 2026-09-21 05:55:12+00:00
- Entities: endpoint_agent_24, security_console4
- Evidence:
  - `RAN-N-00397` | 2026-09-21 05:55:12+00:00 | network_connection | `endpoint_agent_24` → `security_console4` | score 0.33 | Suspicious web activity
### path-019 (score 0.37)
- Time: 2026-09-21 06:23:46+00:00 — 2026-09-21 06:23:46+00:00
- Entities: endpoint_agent_23, security_console15
- Evidence:
  - `RAN-N-00471` | 2026-09-21 06:23:46+00:00 | network_connection | `endpoint_agent_23` → `security_console15` | score 0.33 | Suspicious web activity
### path-020 (score 0.37)
- Time: 2026-09-21 06:46:32+00:00 — 2026-09-21 06:46:32+00:00
- Entities: endpoint_agent_25, security_console11
- Evidence:
  - `RAN-N-00413` | 2026-09-21 06:46:32+00:00 | network_connection | `endpoint_agent_25` → `security_console11` | score 0.33 | Suspicious web activity
### path-021 (score 0.37)
- Time: 2026-09-21 09:32:41+00:00 — 2026-09-21 09:32:41+00:00
- Entities: endpoint_agent_23, security_console10
- Evidence:
  - `RAN-N-00381` | 2026-09-21 09:32:41+00:00 | network_connection | `endpoint_agent_23` → `security_console10` | score 0.33 | Suspicious web activity
### path-022 (score 0.37)
- Time: 2026-09-21 14:47:47+00:00 — 2026-09-21 14:47:47+00:00
- Entities: endpoint_agent_2, security_console15
- Evidence:
  - `RAN-N-00374` | 2026-09-21 14:47:47+00:00 | network_connection | `endpoint_agent_2` → `security_console15` | score 0.33 | Suspicious web activity
### path-023 (score 0.37)
- Time: 2026-09-21 18:19:31+00:00 — 2026-09-21 18:19:31+00:00
- Entities: endpoint_agent_6, security_console18
- Evidence:
  - `RAN-N-00447` | 2026-09-21 18:19:31+00:00 | network_connection | `endpoint_agent_6` → `security_console18` | score 0.33 | Suspicious web activity
### path-024 (score 0.37)
- Time: 2026-09-21 18:46:18+00:00 — 2026-09-21 18:46:18+00:00
- Entities: endpoint_agent_9, security_console10
- Evidence:
  - `RAN-N-00542` | 2026-09-21 18:46:18+00:00 | network_connection | `endpoint_agent_9` → `security_console10` | score 0.33 | Suspicious web activity
### path-025 (score 0.37)
- Time: 2026-09-22 00:04:22+00:00 — 2026-09-22 00:04:22+00:00
- Entities: endpoint_agent_3, security_console11
- Evidence:
  - `RAN-N-00440` | 2026-09-22 00:04:22+00:00 | network_connection | `endpoint_agent_3` → `security_console11` | score 0.33 | Suspicious web activity
### path-026 (score 0.37)
- Time: 2026-09-22 00:08:48+00:00 — 2026-09-22 00:08:48+00:00
- Entities: endpoint_agent_21, security_console8
- Evidence:
  - `RAN-N-00193` | 2026-09-22 00:08:48+00:00 | network_connection | `endpoint_agent_21` → `security_console8` | score 0.33 | Suspicious web activity
### path-027 (score 0.37)
- Time: 2026-09-22 00:22:04+00:00 — 2026-09-22 00:22:04+00:00
- Entities: endpoint_agent_3, security_console16
- Evidence:
  - `RAN-N-00106` | 2026-09-22 00:22:04+00:00 | network_connection | `endpoint_agent_3` → `security_console16` | score 0.33 | Suspicious web activity
### path-028 (score 0.37)
- Time: 2026-09-22 11:25:00+00:00 — 2026-09-22 11:25:00+00:00
- Entities: endpoint_agent_22, security_console14
- Evidence:
  - `RAN-N-00641` | 2026-09-22 11:25:00+00:00 | network_connection | `endpoint_agent_22` → `security_console14` | score 0.33 | Suspicious web activity
### path-029 (score 0.37)
- Time: 2026-09-22 15:53:25+00:00 — 2026-09-22 15:53:25+00:00
- Entities: endpoint_agent_3, security_console12
- Evidence:
  - `RAN-N-00504` | 2026-09-22 15:53:25+00:00 | network_connection | `endpoint_agent_3` → `security_console12` | score 0.33 | Suspicious web activity
### path-030 (score 0.37)
- Time: 2026-09-22 18:19:20+00:00 — 2026-09-22 18:19:20+00:00
- Entities: endpoint_agent_19, security_console4
- Evidence:
  - `RAN-N-00618` | 2026-09-22 18:19:20+00:00 | network_connection | `endpoint_agent_19` → `security_console4` | score 0.33 | Suspicious web activity
### path-031 (score 0.37)
- Time: 2026-09-22 18:20:07+00:00 — 2026-09-22 18:20:07+00:00
- Entities: endpoint_agent_2, security_console1
- Evidence:
  - `RAN-N-00049` | 2026-09-22 18:20:07+00:00 | network_connection | `endpoint_agent_2` → `security_console1` | score 0.33 | Suspicious web activity
### path-032 (score 0.37)
- Time: 2026-09-22 18:28:14+00:00 — 2026-09-22 18:28:14+00:00
- Entities: endpoint_agent_3, security_console15
- Evidence:
  - `RAN-N-00251` | 2026-09-22 18:28:14+00:00 | network_connection | `endpoint_agent_3` → `security_console15` | score 0.33 | Suspicious web activity
### path-033 (score 0.37)
- Time: 2026-09-22 20:07:59+00:00 — 2026-09-22 20:07:59+00:00
- Entities: endpoint_agent_22, security_console7
- Evidence:
  - `RAN-N-00034` | 2026-09-22 20:07:59+00:00 | network_connection | `endpoint_agent_22` → `security_console7` | score 0.33 | Suspicious web activity
### path-034 (score 0.37)
- Time: 2026-09-22 22:34:06+00:00 — 2026-09-22 22:34:06+00:00
- Entities: endpoint_agent_3, security_console3
- Evidence:
  - `RAN-N-00529` | 2026-09-22 22:34:06+00:00 | network_connection | `endpoint_agent_3` → `security_console3` | score 0.33 | Suspicious web activity
### path-037 (score 0.37)
- Time: 2026-09-23 05:54:12+00:00 — 2026-09-23 05:54:12+00:00
- Entities: endpoint_agent_10, security_console11
- Evidence:
  - `RAN-N-00024` | 2026-09-23 05:54:12+00:00 | network_connection | `endpoint_agent_10` → `security_console11` | score 0.33 | Suspicious web activity
### path-038 (score 0.37)
- Time: 2026-09-23 07:20:50+00:00 — 2026-09-23 07:20:50+00:00
- Entities: endpoint_agent_18, security_console9
- Evidence:
  - `RAN-N-00715` | 2026-09-23 07:20:50+00:00 | network_connection | `endpoint_agent_18` → `security_console9` | score 0.33 | Suspicious web activity
### path-039 (score 0.37)
- Time: 2026-09-23 12:38:03+00:00 — 2026-09-23 12:38:03+00:00
- Entities: endpoint_agent_20, security_console18
- Evidence:
  - `RAN-N-00686` | 2026-09-23 12:38:03+00:00 | network_connection | `endpoint_agent_20` → `security_console18` | score 0.33 | Suspicious web activity
### path-041 (score 0.37)
- Time: 2026-09-23 15:00:54+00:00 — 2026-09-23 15:00:54+00:00
- Entities: endpoint_agent_14, security_console16
- Evidence:
  - `RAN-N-00292` | 2026-09-23 15:00:54+00:00 | network_connection | `endpoint_agent_14` → `security_console16` | score 0.33 | Suspicious web activity
### path-044 (score 0.37)
- Time: 2026-09-24 05:50:59+00:00 — 2026-09-24 05:50:59+00:00
- Entities: endpoint_agent_11, security_console18
- Evidence:
  - `RAN-N-00711` | 2026-09-24 05:50:59+00:00 | network_connection | `endpoint_agent_11` → `security_console18` | score 0.33 | Suspicious web activity
### path-045 (score 0.37)
- Time: 2026-09-24 10:36:19+00:00 — 2026-09-24 10:36:19+00:00
- Entities: endpoint_agent_5, security_console15
- Evidence:
  - `RAN-N-00220` | 2026-09-24 10:36:19+00:00 | network_connection | `endpoint_agent_5` → `security_console15` | score 0.33 | Suspicious web activity
### path-046 (score 0.37)
- Time: 2026-09-24 11:31:23+00:00 — 2026-09-24 11:31:23+00:00
- Entities: endpoint_agent_2, security_console17
- Evidence:
  - `RAN-N-00523` | 2026-09-24 11:31:23+00:00 | network_connection | `endpoint_agent_2` → `security_console17` | score 0.33 | Suspicious web activity
### path-047 (score 0.37)
- Time: 2026-09-24 12:02:38+00:00 — 2026-09-24 12:02:38+00:00
- Entities: endpoint_agent_22, security_console9
- Evidence:
  - `RAN-N-00286` | 2026-09-24 12:02:38+00:00 | network_connection | `endpoint_agent_22` → `security_console9` | score 0.33 | Suspicious web activity
### path-048 (score 0.37)
- Time: 2026-09-24 12:37:20+00:00 — 2026-09-24 12:37:20+00:00
- Entities: endpoint_agent_12, security_console6
- Evidence:
  - `RAN-N-00137` | 2026-09-24 12:37:20+00:00 | network_connection | `endpoint_agent_12` → `security_console6` | score 0.33 | Suspicious web activity
### path-049 (score 0.37)
- Time: 2026-09-24 15:59:40+00:00 — 2026-09-24 15:59:40+00:00
- Entities: endpoint_agent_1, security_console13
- Evidence:
  - `RAN-N-00350` | 2026-09-24 15:59:40+00:00 | network_connection | `endpoint_agent_1` → `security_console13` | score 0.33 | Suspicious web activity
### path-050 (score 0.37)
- Time: 2026-09-24 16:14:07+00:00 — 2026-09-24 16:14:07+00:00
- Entities: endpoint_agent_13, security_console12
- Evidence:
  - `RAN-N-00470` | 2026-09-24 16:14:07+00:00 | network_connection | `endpoint_agent_13` → `security_console12` | score 0.33 | Suspicious web activity
### path-051 (score 0.37)
- Time: 2026-09-24 16:47:56+00:00 — 2026-09-24 16:47:56+00:00
- Entities: endpoint_agent_6, security_console1
- Evidence:
  - `RAN-N-00603` | 2026-09-24 16:47:56+00:00 | network_connection | `endpoint_agent_6` → `security_console1` | score 0.33 | Suspicious web activity
### path-052 (score 0.37)
- Time: 2026-09-24 18:30:31+00:00 — 2026-09-24 18:30:31+00:00
- Entities: endpoint_agent_5, security_console3
- Evidence:
  - `RAN-N-00394` | 2026-09-24 18:30:31+00:00 | network_connection | `endpoint_agent_5` → `security_console3` | score 0.33 | Suspicious web activity
### path-053 (score 0.37)
- Time: 2026-09-24 22:58:15+00:00 — 2026-09-24 22:58:15+00:00
- Entities: endpoint_agent_9, security_console10
- Evidence:
  - `RAN-N-00025` | 2026-09-24 22:58:15+00:00 | network_connection | `endpoint_agent_9` → `security_console10` | score 0.33 | Suspicious web activity
### path-054 (score 0.37)
- Time: 2026-09-24 23:21:27+00:00 — 2026-09-24 23:21:27+00:00
- Entities: endpoint_agent_17, security_console2
- Evidence:
  - `RAN-N-00039` | 2026-09-24 23:21:27+00:00 | network_connection | `endpoint_agent_17` → `security_console2` | score 0.33 | Suspicious web activity
### path-055 (score 0.37)
- Time: 2026-09-24 23:33:28+00:00 — 2026-09-24 23:33:28+00:00
- Entities: endpoint_agent_25, security_console16
- Evidence:
  - `RAN-N-00152` | 2026-09-24 23:33:28+00:00 | network_connection | `endpoint_agent_25` → `security_console16` | score 0.33 | Suspicious web activity
### path-056 (score 0.37)
- Time: 2026-09-25 01:43:33+00:00 — 2026-09-25 01:43:33+00:00
- Entities: endpoint_agent_9, security_console11
- Evidence:
  - `RAN-N-00221` | 2026-09-25 01:43:33+00:00 | network_connection | `endpoint_agent_9` → `security_console11` | score 0.33 | Suspicious web activity
### path-057 (score 0.37)
- Time: 2026-09-25 03:05:29+00:00 — 2026-09-25 03:05:29+00:00
- Entities: endpoint_agent_6, security_console8
- Evidence:
  - `RAN-N-00553` | 2026-09-25 03:05:29+00:00 | network_connection | `endpoint_agent_6` → `security_console8` | score 0.33 | Suspicious web activity
### path-058 (score 0.37)
- Time: 2026-09-25 03:30:32+00:00 — 2026-09-25 03:30:32+00:00
- Entities: endpoint_agent_1, security_console11
- Evidence:
  - `RAN-N-00409` | 2026-09-25 03:30:32+00:00 | network_connection | `endpoint_agent_1` → `security_console11` | score 0.33 | Suspicious web activity
### path-059 (score 0.37)
- Time: 2026-09-25 03:46:02+00:00 — 2026-09-25 03:46:02+00:00
- Entities: endpoint_agent_16, security_console16
- Evidence:
  - `RAN-N-00435` | 2026-09-25 03:46:02+00:00 | network_connection | `endpoint_agent_16` → `security_console16` | score 0.33 | Suspicious web activity
### path-060 (score 0.37)
- Time: 2026-09-25 11:09:36+00:00 — 2026-09-25 11:09:36+00:00
- Entities: endpoint_agent_22, security_console8
- Evidence:
  - `RAN-N-00006` | 2026-09-25 11:09:36+00:00 | network_connection | `endpoint_agent_22` → `security_console8` | score 0.33 | Suspicious web activity
### path-061 (score 0.37)
- Time: 2026-09-25 11:26:35+00:00 — 2026-09-25 11:26:35+00:00
- Entities: endpoint_agent_23, security_console11
- Evidence:
  - `RAN-N-00172` | 2026-09-25 11:26:35+00:00 | network_connection | `endpoint_agent_23` → `security_console11` | score 0.33 | Suspicious web activity
### path-062 (score 0.37)
- Time: 2026-09-25 11:52:06+00:00 — 2026-09-25 11:52:06+00:00
- Entities: endpoint_agent_21, security_console14
- Evidence:
  - `RAN-N-00480` | 2026-09-25 11:52:06+00:00 | network_connection | `endpoint_agent_21` → `security_console14` | score 0.33 | Suspicious web activity
### path-063 (score 0.37)
- Time: 2026-09-25 13:34:48+00:00 — 2026-09-25 13:34:48+00:00
- Entities: endpoint_agent_20, security_console12
- Evidence:
  - `RAN-N-00514` | 2026-09-25 13:34:48+00:00 | network_connection | `endpoint_agent_20` → `security_console12` | score 0.33 | Suspicious web activity
### path-064 (score 0.37)
- Time: 2026-09-25 13:49:14+00:00 — 2026-09-25 13:49:14+00:00
- Entities: endpoint_agent_9, security_console16
- Evidence:
  - `RAN-N-00710` | 2026-09-25 13:49:14+00:00 | network_connection | `endpoint_agent_9` → `security_console16` | score 0.33 | Suspicious web activity
### path-065 (score 0.37)
- Time: 2026-09-25 15:34:33+00:00 — 2026-09-25 15:34:33+00:00
- Entities: endpoint_agent_16, security_console11
- Evidence:
  - `RAN-N-00425` | 2026-09-25 15:34:33+00:00 | network_connection | `endpoint_agent_16` → `security_console11` | score 0.33 | Suspicious web activity
### path-066 (score 0.37)
- Time: 2026-09-25 16:21:32+00:00 — 2026-09-25 16:21:32+00:00
- Entities: endpoint_agent_1, security_console5
- Evidence:
  - `RAN-N-00028` | 2026-09-25 16:21:32+00:00 | network_connection | `endpoint_agent_1` → `security_console5` | score 0.33 | Suspicious web activity
### path-067 (score 0.37)
- Time: 2026-09-25 16:31:20+00:00 — 2026-09-25 16:31:20+00:00
- Entities: endpoint_agent_7, security_console8
- Evidence:
  - `RAN-N-00051` | 2026-09-25 16:31:20+00:00 | network_connection | `endpoint_agent_7` → `security_console8` | score 0.33 | Suspicious web activity
### path-068 (score 0.37)
- Time: 2026-09-25 17:29:12+00:00 — 2026-09-25 17:29:12+00:00
- Entities: endpoint_agent_6, security_console11
- Evidence:
  - `RAN-N-00271` | 2026-09-25 17:29:12+00:00 | network_connection | `endpoint_agent_6` → `security_console11` | score 0.33 | Suspicious web activity
### path-069 (score 0.37)
- Time: 2026-09-25 19:02:44+00:00 — 2026-09-25 19:02:44+00:00
- Entities: endpoint_agent_19, security_console17
- Evidence:
  - `RAN-N-00151` | 2026-09-25 19:02:44+00:00 | network_connection | `endpoint_agent_19` → `security_console17` | score 0.33 | Suspicious web activity
### path-070 (score 0.37)
- Time: 2026-09-25 19:27:39+00:00 — 2026-09-25 19:27:39+00:00
- Entities: endpoint_agent_22, security_console10
- Evidence:
  - `RAN-N-00267` | 2026-09-25 19:27:39+00:00 | network_connection | `endpoint_agent_22` → `security_console10` | score 0.33 | Suspicious web activity
### path-071 (score 0.37)
- Time: 2026-09-25 19:33:23+00:00 — 2026-09-25 19:33:23+00:00
- Entities: endpoint_agent_10, security_console4
- Evidence:
  - `RAN-N-00311` | 2026-09-25 19:33:23+00:00 | network_connection | `endpoint_agent_10` → `security_console4` | score 0.33 | Suspicious web activity
### path-072 (score 0.37)
- Time: 2026-09-25 22:33:37+00:00 — 2026-09-25 22:33:37+00:00
- Entities: endpoint_agent_11, security_console16
- Evidence:
  - `RAN-N-00276` | 2026-09-25 22:33:37+00:00 | network_connection | `endpoint_agent_11` → `security_console16` | score 0.33 | Suspicious web activity
### path-073 (score 0.37)
- Time: 2026-09-26 00:09:09+00:00 — 2026-09-26 00:09:09+00:00
- Entities: endpoint_agent_25, security_console3
- Evidence:
  - `RAN-N-00365` | 2026-09-26 00:09:09+00:00 | network_connection | `endpoint_agent_25` → `security_console3` | score 0.33 | Suspicious web activity
### path-074 (score 0.37)
- Time: 2026-09-26 00:41:23+00:00 — 2026-09-26 00:41:23+00:00
- Entities: endpoint_agent_19, security_console12
- Evidence:
  - `RAN-N-00371` | 2026-09-26 00:41:23+00:00 | network_connection | `endpoint_agent_19` → `security_console12` | score 0.33 | Suspicious web activity
### path-075 (score 0.37)
- Time: 2026-09-26 03:15:06+00:00 — 2026-09-26 03:15:06+00:00
- Entities: endpoint_agent_17, security_console16
- Evidence:
  - `RAN-N-00191` | 2026-09-26 03:15:06+00:00 | network_connection | `endpoint_agent_17` → `security_console16` | score 0.33 | Suspicious web activity
### path-076 (score 0.37)
- Time: 2026-09-26 07:46:54+00:00 — 2026-09-26 07:46:54+00:00
- Entities: endpoint_agent_21, security_console6
- Evidence:
  - `RAN-N-00023` | 2026-09-26 07:46:54+00:00 | network_connection | `endpoint_agent_21` → `security_console6` | score 0.33 | Suspicious web activity
### path-077 (score 0.37)
- Time: 2026-09-26 09:44:34+00:00 — 2026-09-26 09:44:34+00:00
- Entities: endpoint_agent_9, security_console18
- Evidence:
  - `RAN-N-00357` | 2026-09-26 09:44:34+00:00 | network_connection | `endpoint_agent_9` → `security_console18` | score 0.33 | Suspicious web activity
### path-078 (score 0.37)
- Time: 2026-09-26 11:00:08+00:00 — 2026-09-26 11:00:08+00:00
- Entities: endpoint_agent_25, security_console4
- Evidence:
  - `RAN-N-00630` | 2026-09-26 11:00:08+00:00 | network_connection | `endpoint_agent_25` → `security_console4` | score 0.33 | Suspicious web activity
### path-080 (score 0.37)
- Time: 2026-09-26 12:03:29+00:00 — 2026-09-26 12:03:29+00:00
- Entities: endpoint_agent_17, security_console18
- Evidence:
  - `RAN-N-00244` | 2026-09-26 12:03:29+00:00 | network_connection | `endpoint_agent_17` → `security_console18` | score 0.33 | Suspicious web activity
### path-081 (score 0.37)
- Time: 2026-09-26 12:41:47+00:00 — 2026-09-26 12:41:47+00:00
- Entities: endpoint_agent_4, security_console2
- Evidence:
  - `RAN-N-00147` | 2026-09-26 12:41:47+00:00 | network_connection | `endpoint_agent_4` → `security_console2` | score 0.33 | Suspicious web activity
### path-082 (score 0.37)
- Time: 2026-09-26 19:42:12+00:00 — 2026-09-26 19:42:12+00:00
- Entities: endpoint_agent_6, security_console14
- Evidence:
  - `RAN-N-00631` | 2026-09-26 19:42:12+00:00 | network_connection | `endpoint_agent_6` → `security_console14` | score 0.33 | Suspicious web activity
### path-083 (score 0.37)
- Time: 2026-09-26 22:09:35+00:00 — 2026-09-26 22:09:35+00:00
- Entities: endpoint_agent_2, security_console4
- Evidence:
  - `RAN-N-00484` | 2026-09-26 22:09:35+00:00 | network_connection | `endpoint_agent_2` → `security_console4` | score 0.33 | Suspicious web activity
### path-084 (score 0.37)
- Time: 2026-09-26 22:48:55+00:00 — 2026-09-26 22:48:55+00:00
- Entities: endpoint_agent_21, security_console14
- Evidence:
  - `RAN-N-00685` | 2026-09-26 22:48:55+00:00 | network_connection | `endpoint_agent_21` → `security_console14` | score 0.33 | Suspicious web activity

## Candidate MITRE ATT&CK mappings
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-002` at 2026-09-23 04:00:35+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: powershell encoded command execution from invoice document
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-003` at 2026-09-23 04:01:10+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: credential access indicator; LSASS password dump attempt
- **[T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)** — event `RAN-A-003` at 2026-09-23 04:01:10+00:00: Credential-dumping indicator; confirm with endpoint evidence. Evidence: credential access indicator; LSASS password dump attempt
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-004` at 2026-09-23 04:01:45+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: unusual external destination after script execution
- **[T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)** — event `RAN-A-004` at 2026-09-23 04:01:45+00:00: Script or command execution indicator; confirm the interpreter and command. Evidence: unusual external destination after script execution
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-005` at 2026-09-23 04:02:40+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Accessed sensitive payroll and customer_db files
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-006` at 2026-09-23 04:03:40+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Sensitive data staging and archive compression
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `RAN-A-006` at 2026-09-23 04:03:40+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Sensitive data staging and archive compression
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `RAN-A-007` at 2026-09-23 04:04:50+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Lateral movement attempt toward file server
- **[T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)** — event `RAN-A-008` at 2026-09-23 04:06:00+00:00: Encryption/ransomware-like indicator; verify file-operation evidence. Evidence: ransomware mass_file encryption behavior
- **[T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)** — event `RAN-A-009` at 2026-09-23 04:07:00+00:00: Encryption/ransomware-like indicator; verify file-operation evidence. Evidence: ransomware attempted shadow_copy deletion

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.