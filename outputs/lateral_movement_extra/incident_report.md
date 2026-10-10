# RansomTrace AI Incident Report — lateral_movement_extra

## Summary
- Events analyzed: **719**
- Events flagged: **227**
- Candidate paths: **222**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 719,
  "ground_truth_attack_events": 9,
  "detected_events": 227,
  "true_positives": 9,
  "false_positives": 218,
  "false_negatives": 0,
  "precision": 0.0396,
  "recall": 1.0,
  "f1": 0.0763,
  "attack_event_recall": 1.0,
  "original_nodes": 280,
  "reduced_nodes": 277,
  "node_reduction_pct": 1.07,
  "original_edges": 719,
  "reduced_edges": 681,
  "edge_reduction_pct": 5.29,
  "attack_events_retained_in_reduced_graph": 9,
  "attack_event_retention_pct": 100.0,
  "retained_attack_event_ids": [
    "LAT-A-001",
    "LAT-A-002",
    "LAT-A-003",
    "LAT-A-004",
    "LAT-A-005",
    "LAT-A-006",
    "LAT-A-007",
    "LAT-A-008",
    "LAT-A-009"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-086 (score 0.87)
- Time: 2026-09-23 04:01:05+00:00 — 2026-09-23 04:01:40+00:00
- Entities: admin_token, credential_cache, powershell.exe
- Evidence:
  - `LAT-A-003` | 2026-09-23 04:01:05+00:00 | file_read | `powershell.exe` → `credential_cache` | score 0.6499999999999999 | Script/command execution; Credential-access indicator
  - `LAT-A-004` | 2026-09-23 04:01:40+00:00 | process_start | `powershell.exe` → `admin_token` | score 0.93 | Privilege-related activity; Script/command execution; Credential-access indicator
### path-089 (score 0.755)
- Time: 2026-09-23 04:05:00+00:00 — 2026-09-23 04:05:55+00:00
- Entities: payroll_archive.zip, powershell.exe, unknown_ip_192.0.2.88
- Evidence:
  - `LAT-A-008` | 2026-09-23 04:05:00+00:00 | file_write | `powershell.exe` → `payroll_archive.zip` | score 0.55 | Script/command execution; Sensitive data/staging indicator
  - `LAT-A-009` | 2026-09-23 04:05:55+00:00 | network_connection | `powershell.exe` → `unknown_ip_192.0.2.88` | score 0.8 | Script/command execution; Sensitive data/staging indicator; Unusual destination
### path-085 (score 0.545)
- Time: 2026-09-23 04:00:00+00:00 — 2026-09-23 04:00:30+00:00
- Entities: endpoint-01, user_18
- Evidence:
  - `LAT-A-001` | 2026-09-23 04:00:00+00:00 | login_failed | `user_18` → `endpoint-01` | score 0.63 | Authentication failures; Unusual destination; Uncommon event type
  - `LAT-A-002` | 2026-09-23 04:00:30+00:00 | login_success | `user_18` → `endpoint-01` | score 0.3 | Authentication failures
### path-088 (score 0.45)
- Time: 2026-09-23 04:03:10+00:00 — 2026-09-23 04:04:05+00:00
- Entities: admin-jump-01, fileserver-01, user_18@endpoint-01
- Evidence:
  - `LAT-A-006` | 2026-09-23 04:03:10+00:00 | remote_service_login | `user_18@endpoint-01` → `admin-jump-01` | score 0.41000000000000003 | Privilege-related activity; Uncommon event type
  - `LAT-A-007` | 2026-09-23 04:04:05+00:00 | network_connection | `admin-jump-01` → `fileserver-01` | score 0.33 | Privilege-related activity
### path-014 (score 0.41)
- Time: 2026-09-20 09:34:03+00:00 — 2026-09-20 11:56:07+00:00
- Entities: admin_11, admin_18, patch_server8
- Evidence:
  - `LAT-N-00361` | 2026-09-20 09:34:03+00:00 | network_connection | `admin_18` → `patch_server8` | score 0.33 | Privilege-related activity
  - `LAT-N-00100` | 2026-09-20 11:56:07+00:00 | network_connection | `admin_11` → `patch_server8` | score 0.33 | Privilege-related activity
### path-001 (score 0.37)
- Time: 2026-09-20 00:21:05+00:00 — 2026-09-20 00:21:05+00:00
- Entities: admin_7, patch_server7
- Evidence:
  - `LAT-N-00038` | 2026-09-20 00:21:05+00:00 | network_connection | `admin_7` → `patch_server7` | score 0.33 | Privilege-related activity
### path-002 (score 0.37)
- Time: 2026-09-20 00:30:27+00:00 — 2026-09-20 00:30:27+00:00
- Entities: admin_13, patch_server14
- Evidence:
  - `LAT-N-00497` | 2026-09-20 00:30:27+00:00 | network_connection | `admin_13` → `patch_server14` | score 0.33 | Privilege-related activity
### path-003 (score 0.37)
- Time: 2026-09-20 00:38:05+00:00 — 2026-09-20 00:38:05+00:00
- Entities: employee_2, identity_service9
- Evidence:
  - `LAT-N-00172` | 2026-09-20 00:38:05+00:00 | login_success | `employee_2` → `identity_service9` | score 0.33 | Privilege-related activity
### path-004 (score 0.37)
- Time: 2026-09-20 01:25:32+00:00 — 2026-09-20 01:25:32+00:00
- Entities: admin_25, patch_server2
- Evidence:
  - `LAT-N-00489` | 2026-09-20 01:25:32+00:00 | network_connection | `admin_25` → `patch_server2` | score 0.33 | Privilege-related activity
### path-005 (score 0.37)
- Time: 2026-09-20 02:29:33+00:00 — 2026-09-20 02:29:33+00:00
- Entities: employee_16, vpn_gateway15
- Evidence:
  - `LAT-N-00107` | 2026-09-20 02:29:33+00:00 | login_success | `employee_16` → `vpn_gateway15` | score 0.33 | Privilege-related activity
### path-006 (score 0.37)
- Time: 2026-09-20 02:55:01+00:00 — 2026-09-20 02:55:01+00:00
- Entities: admin_1, patch_server5
- Evidence:
  - `LAT-N-00661` | 2026-09-20 02:55:01+00:00 | network_connection | `admin_1` → `patch_server5` | score 0.33 | Privilege-related activity
### path-007 (score 0.37)
- Time: 2026-09-20 04:54:54+00:00 — 2026-09-20 04:54:54+00:00
- Entities: edr_console3, endpoint_agent_6
- Evidence:
  - `LAT-N-00061` | 2026-09-20 04:54:54+00:00 | network_connection | `endpoint_agent_6` → `edr_console3` | score 0.33 | Privilege-related activity
### path-008 (score 0.37)
- Time: 2026-09-20 05:03:21+00:00 — 2026-09-20 05:03:21+00:00
- Entities: admin_5, patch_server13
- Evidence:
  - `LAT-N-00023` | 2026-09-20 05:03:21+00:00 | network_connection | `admin_5` → `patch_server13` | score 0.33 | Privilege-related activity
### path-009 (score 0.37)
- Time: 2026-09-20 05:33:17+00:00 — 2026-09-20 05:33:17+00:00
- Entities: admin_4, patch_server7
- Evidence:
  - `LAT-N-00583` | 2026-09-20 05:33:17+00:00 | network_connection | `admin_4` → `patch_server7` | score 0.33 | Privilege-related activity
### path-010 (score 0.37)
- Time: 2026-09-20 06:03:07+00:00 — 2026-09-20 06:03:07+00:00
- Entities: employee_6, identity_service4
- Evidence:
  - `LAT-N-00094` | 2026-09-20 06:03:07+00:00 | login_success | `employee_6` → `identity_service4` | score 0.33 | Privilege-related activity
### path-011 (score 0.37)
- Time: 2026-09-20 06:48:30+00:00 — 2026-09-20 06:48:30+00:00
- Entities: employee_16, identity_service18
- Evidence:
  - `LAT-N-00033` | 2026-09-20 06:48:30+00:00 | login_success | `employee_16` → `identity_service18` | score 0.33 | Privilege-related activity
### path-012 (score 0.37)
- Time: 2026-09-20 08:53:22+00:00 — 2026-09-20 08:53:22+00:00
- Entities: admin_19, patch_server11
- Evidence:
  - `LAT-N-00263` | 2026-09-20 08:53:22+00:00 | network_connection | `admin_19` → `patch_server11` | score 0.33 | Privilege-related activity
### path-013 (score 0.37)
- Time: 2026-09-20 09:29:50+00:00 — 2026-09-20 09:29:50+00:00
- Entities: admin_16, patch_server18
- Evidence:
  - `LAT-N-00480` | 2026-09-20 09:29:50+00:00 | network_connection | `admin_16` → `patch_server18` | score 0.33 | Privilege-related activity
### path-015 (score 0.37)
- Time: 2026-09-20 13:01:49+00:00 — 2026-09-20 13:01:49+00:00
- Entities: admin_8, patch_server7
- Evidence:
  - `LAT-N-00515` | 2026-09-20 13:01:49+00:00 | network_connection | `admin_8` → `patch_server7` | score 0.33 | Privilege-related activity
### path-016 (score 0.37)
- Time: 2026-09-20 13:13:58+00:00 — 2026-09-20 13:13:58+00:00
- Entities: host_21, internal_dns8
- Evidence:
  - `LAT-N-00352` | 2026-09-20 13:13:58+00:00 | dns_query | `host_21` → `internal_dns8` | score 0.33 | Privilege-related activity
### path-017 (score 0.37)
- Time: 2026-09-20 14:11:33+00:00 — 2026-09-20 14:11:33+00:00
- Entities: admin_21, patch_server10
- Evidence:
  - `LAT-N-00568` | 2026-09-20 14:11:33+00:00 | network_connection | `admin_21` → `patch_server10` | score 0.33 | Privilege-related activity
### path-018 (score 0.37)
- Time: 2026-09-20 14:57:44+00:00 — 2026-09-20 14:57:44+00:00
- Entities: host_8, internal_dns15
- Evidence:
  - `LAT-N-00110` | 2026-09-20 14:57:44+00:00 | dns_query | `host_8` → `internal_dns15` | score 0.33 | Privilege-related activity
### path-019 (score 0.37)
- Time: 2026-09-20 16:45:24+00:00 — 2026-09-20 16:45:24+00:00
- Entities: admin_11, patch_server2
- Evidence:
  - `LAT-N-00039` | 2026-09-20 16:45:24+00:00 | network_connection | `admin_11` → `patch_server2` | score 0.33 | Privilege-related activity
### path-020 (score 0.37)
- Time: 2026-09-20 16:50:56+00:00 — 2026-09-20 16:50:56+00:00
- Entities: host_4, internal_dns10
- Evidence:
  - `LAT-N-00381` | 2026-09-20 16:50:56+00:00 | dns_query | `host_4` → `internal_dns10` | score 0.33 | Privilege-related activity
### path-021 (score 0.37)
- Time: 2026-09-20 17:40:06+00:00 — 2026-09-20 17:40:06+00:00
- Entities: employee_18, identity_service14
- Evidence:
  - `LAT-N-00412` | 2026-09-20 17:40:06+00:00 | login_success | `employee_18` → `identity_service14` | score 0.33 | Privilege-related activity
### path-022 (score 0.37)
- Time: 2026-09-20 18:24:28+00:00 — 2026-09-20 18:24:28+00:00
- Entities: admin_23, patch_server17
- Evidence:
  - `LAT-N-00116` | 2026-09-20 18:24:28+00:00 | network_connection | `admin_23` → `patch_server17` | score 0.33 | Privilege-related activity
### path-023 (score 0.37)
- Time: 2026-09-20 18:25:54+00:00 — 2026-09-20 18:25:54+00:00
- Entities: admin_17, patch_server7
- Evidence:
  - `LAT-N-00439` | 2026-09-20 18:25:54+00:00 | network_connection | `admin_17` → `patch_server7` | score 0.33 | Privilege-related activity
### path-024 (score 0.37)
- Time: 2026-09-20 19:52:49+00:00 — 2026-09-20 19:52:49+00:00
- Entities: admin_7, patch_server5
- Evidence:
  - `LAT-N-00321` | 2026-09-20 19:52:49+00:00 | network_connection | `admin_7` → `patch_server5` | score 0.33 | Privilege-related activity
### path-025 (score 0.37)
- Time: 2026-09-20 20:17:16+00:00 — 2026-09-20 20:17:16+00:00
- Entities: admin_19, patch_server14
- Evidence:
  - `LAT-N-00691` | 2026-09-20 20:17:16+00:00 | network_connection | `admin_19` → `patch_server14` | score 0.33 | Privilege-related activity
### path-026 (score 0.37)
- Time: 2026-09-20 21:51:42+00:00 — 2026-09-20 21:51:42+00:00
- Entities: admin_22, patch_server12
- Evidence:
  - `LAT-N-00423` | 2026-09-20 21:51:42+00:00 | network_connection | `admin_22` → `patch_server12` | score 0.33 | Privilege-related activity
### path-027 (score 0.37)
- Time: 2026-09-20 22:09:12+00:00 — 2026-09-20 22:09:12+00:00
- Entities: employee_10, vpn_gateway12
- Evidence:
  - `LAT-N-00173` | 2026-09-20 22:09:12+00:00 | login_success | `employee_10` → `vpn_gateway12` | score 0.33 | Privilege-related activity
### path-028 (score 0.37)
- Time: 2026-09-20 22:28:11+00:00 — 2026-09-20 22:28:11+00:00
- Entities: admin_23, patch_server14
- Evidence:
  - `LAT-N-00036` | 2026-09-20 22:28:11+00:00 | network_connection | `admin_23` → `patch_server14` | score 0.33 | Privilege-related activity
### path-029 (score 0.37)
- Time: 2026-09-20 23:20:54+00:00 — 2026-09-20 23:20:54+00:00
- Entities: edr_console3, endpoint_agent_13
- Evidence:
  - `LAT-N-00122` | 2026-09-20 23:20:54+00:00 | network_connection | `endpoint_agent_13` → `edr_console3` | score 0.33 | Privilege-related activity
### path-030 (score 0.37)
- Time: 2026-09-20 23:27:28+00:00 — 2026-09-20 23:27:28+00:00
- Entities: admin_19, patch_server1
- Evidence:
  - `LAT-N-00233` | 2026-09-20 23:27:28+00:00 | network_connection | `admin_19` → `patch_server1` | score 0.33 | Privilege-related activity
### path-031 (score 0.37)
- Time: 2026-09-20 23:32:50+00:00 — 2026-09-20 23:32:50+00:00
- Entities: shared_folder8, user_20
- Evidence:
  - `LAT-N-00522` | 2026-09-20 23:32:50+00:00 | file_read | `user_20` → `shared_folder8` | score 0.33 | Privilege-related activity
### path-032 (score 0.37)
- Time: 2026-09-20 23:36:57+00:00 — 2026-09-20 23:36:57+00:00
- Entities: host_15, internal_dns13
- Evidence:
  - `LAT-N-00098` | 2026-09-20 23:36:57+00:00 | dns_query | `host_15` → `internal_dns13` | score 0.33 | Privilege-related activity
### path-033 (score 0.37)
- Time: 2026-09-21 02:54:17+00:00 — 2026-09-21 02:54:17+00:00
- Entities: scheduled_task12, service_account_25
- Evidence:
  - `LAT-N-00024` | 2026-09-21 02:54:17+00:00 | process_start | `service_account_25` → `scheduled_task12` | score 0.33 | Privilege-related activity
### path-034 (score 0.37)
- Time: 2026-09-21 03:11:28+00:00 — 2026-09-21 03:11:28+00:00
- Entities: admin_1, patch_server17
- Evidence:
  - `LAT-N-00251` | 2026-09-21 03:11:28+00:00 | network_connection | `admin_1` → `patch_server17` | score 0.33 | Privilege-related activity
### path-035 (score 0.37)
- Time: 2026-09-21 03:54:04+00:00 — 2026-09-21 03:54:04+00:00
- Entities: host_2, internal_dns6
- Evidence:
  - `LAT-N-00288` | 2026-09-21 03:54:04+00:00 | dns_query | `host_2` → `internal_dns6` | score 0.33 | Privilege-related activity
### path-036 (score 0.37)
- Time: 2026-09-21 05:38:51+00:00 — 2026-09-21 05:38:51+00:00
- Entities: scheduled_task5, service_account_10
- Evidence:
  - `LAT-N-00244` | 2026-09-21 05:38:51+00:00 | process_start | `service_account_10` → `scheduled_task5` | score 0.33 | Privilege-related activity
### path-037 (score 0.37)
- Time: 2026-09-21 05:51:22+00:00 — 2026-09-21 05:51:22+00:00
- Entities: edr_console14, endpoint_agent_5
- Evidence:
  - `LAT-N-00285` | 2026-09-21 05:51:22+00:00 | network_connection | `endpoint_agent_5` → `edr_console14` | score 0.33 | Privilege-related activity
### path-038 (score 0.37)
- Time: 2026-09-21 06:35:55+00:00 — 2026-09-21 06:35:55+00:00
- Entities: admin_18, patch_server17
- Evidence:
  - `LAT-N-00471` | 2026-09-21 06:35:55+00:00 | network_connection | `admin_18` → `patch_server17` | score 0.33 | Privilege-related activity
### path-039 (score 0.37)
- Time: 2026-09-21 10:53:27+00:00 — 2026-09-21 10:53:27+00:00
- Entities: scheduled_task9, service_account_20
- Evidence:
  - `LAT-N-00165` | 2026-09-21 10:53:27+00:00 | process_start | `service_account_20` → `scheduled_task9` | score 0.33 | Privilege-related activity
### path-040 (score 0.37)
- Time: 2026-09-21 11:53:36+00:00 — 2026-09-21 11:53:36+00:00
- Entities: scheduled_task4, service_account_5
- Evidence:
  - `LAT-N-00137` | 2026-09-21 11:53:36+00:00 | process_start | `service_account_5` → `scheduled_task4` | score 0.33 | Privilege-related activity
### path-041 (score 0.37)
- Time: 2026-09-21 12:34:26+00:00 — 2026-09-21 12:34:26+00:00
- Entities: scheduled_task8, service_account_24
- Evidence:
  - `LAT-N-00083` | 2026-09-21 12:34:26+00:00 | process_start | `service_account_24` → `scheduled_task8` | score 0.33 | Privilege-related activity
### path-042 (score 0.37)
- Time: 2026-09-21 13:03:31+00:00 — 2026-09-21 13:03:31+00:00
- Entities: admin_2, patch_server8
- Evidence:
  - `LAT-N-00666` | 2026-09-21 13:03:31+00:00 | network_connection | `admin_2` → `patch_server8` | score 0.33 | Privilege-related activity
### path-043 (score 0.37)
- Time: 2026-09-21 14:23:19+00:00 — 2026-09-21 14:23:19+00:00
- Entities: admin_25, patch_server7
- Evidence:
  - `LAT-N-00647` | 2026-09-21 14:23:19+00:00 | network_connection | `admin_25` → `patch_server7` | score 0.33 | Privilege-related activity
### path-044 (score 0.37)
- Time: 2026-09-21 15:05:50+00:00 — 2026-09-21 15:05:50+00:00
- Entities: admin_18, patch_server18
- Evidence:
  - `LAT-N-00380` | 2026-09-21 15:05:50+00:00 | network_connection | `admin_18` → `patch_server18` | score 0.33 | Privilege-related activity
### path-045 (score 0.37)
- Time: 2026-09-21 16:52:38+00:00 — 2026-09-21 16:52:38+00:00
- Entities: shared_folder12, user_16
- Evidence:
  - `LAT-N-00294` | 2026-09-21 16:52:38+00:00 | file_read | `user_16` → `shared_folder12` | score 0.33 | Privilege-related activity
### path-046 (score 0.37)
- Time: 2026-09-21 18:19:27+00:00 — 2026-09-21 18:19:27+00:00
- Entities: employee_23, vpn_gateway9
- Evidence:
  - `LAT-N-00433` | 2026-09-21 18:19:27+00:00 | login_success | `employee_23` → `vpn_gateway9` | score 0.33 | Privilege-related activity
### path-047 (score 0.37)
- Time: 2026-09-21 18:22:27+00:00 — 2026-09-21 18:22:27+00:00
- Entities: employee_14, vpn_gateway1
- Evidence:
  - `LAT-N-00665` | 2026-09-21 18:22:27+00:00 | login_success | `employee_14` → `vpn_gateway1` | score 0.33 | Privilege-related activity
### path-048 (score 0.37)
- Time: 2026-09-21 18:48:47+00:00 — 2026-09-21 18:48:47+00:00
- Entities: admin_5, patch_server14
- Evidence:
  - `LAT-N-00266` | 2026-09-21 18:48:47+00:00 | network_connection | `admin_5` → `patch_server14` | score 0.33 | Privilege-related activity
### path-049 (score 0.37)
- Time: 2026-09-21 19:07:33+00:00 — 2026-09-21 19:07:33+00:00
- Entities: admin_12, patch_server15
- Evidence:
  - `LAT-N-00623` | 2026-09-21 19:07:33+00:00 | network_connection | `admin_12` → `patch_server15` | score 0.33 | Privilege-related activity
### path-050 (score 0.37)
- Time: 2026-09-21 19:17:25+00:00 — 2026-09-21 19:17:25+00:00
- Entities: admin_13, patch_server6
- Evidence:
  - `LAT-N-00539` | 2026-09-21 19:17:25+00:00 | network_connection | `admin_13` → `patch_server6` | score 0.33 | Privilege-related activity
### path-051 (score 0.37)
- Time: 2026-09-22 00:19:52+00:00 — 2026-09-22 00:19:52+00:00
- Entities: admin_10, patch_server3
- Evidence:
  - `LAT-N-00270` | 2026-09-22 00:19:52+00:00 | network_connection | `admin_10` → `patch_server3` | score 0.33 | Privilege-related activity
### path-052 (score 0.37)
- Time: 2026-09-22 00:34:41+00:00 — 2026-09-22 00:34:41+00:00
- Entities: employee_8, vpn_gateway16
- Evidence:
  - `LAT-N-00258` | 2026-09-22 00:34:41+00:00 | login_success | `employee_8` → `vpn_gateway16` | score 0.33 | Privilege-related activity
### path-053 (score 0.37)
- Time: 2026-09-22 01:20:57+00:00 — 2026-09-22 01:20:57+00:00
- Entities: scheduled_task10, service_account_13
- Evidence:
  - `LAT-N-00637` | 2026-09-22 01:20:57+00:00 | process_start | `service_account_13` → `scheduled_task10` | score 0.33 | Privilege-related activity
### path-054 (score 0.37)
- Time: 2026-09-22 01:22:52+00:00 — 2026-09-22 01:22:52+00:00
- Entities: admin_24, patch_server15
- Evidence:
  - `LAT-N-00553` | 2026-09-22 01:22:52+00:00 | network_connection | `admin_24` → `patch_server15` | score 0.33 | Privilege-related activity
### path-055 (score 0.37)
- Time: 2026-09-22 01:24:36+00:00 — 2026-09-22 01:24:36+00:00
- Entities: admin_1, patch_server2
- Evidence:
  - `LAT-N-00324` | 2026-09-22 01:24:36+00:00 | network_connection | `admin_1` → `patch_server2` | score 0.33 | Privilege-related activity
### path-056 (score 0.37)
- Time: 2026-09-22 03:02:06+00:00 — 2026-09-22 03:02:06+00:00
- Entities: host_20, internal_dns14
- Evidence:
  - `LAT-N-00347` | 2026-09-22 03:02:06+00:00 | dns_query | `host_20` → `internal_dns14` | score 0.33 | Privilege-related activity
### path-057 (score 0.37)
- Time: 2026-09-22 03:09:50+00:00 — 2026-09-22 03:09:50+00:00
- Entities: scheduled_task13, service_account_6
- Evidence:
  - `LAT-N-00706` | 2026-09-22 03:09:50+00:00 | process_start | `service_account_6` → `scheduled_task13` | score 0.33 | Privilege-related activity
### path-058 (score 0.37)
- Time: 2026-09-22 03:58:53+00:00 — 2026-09-22 03:58:53+00:00
- Entities: scheduled_task18, service_account_16
- Evidence:
  - `LAT-N-00198` | 2026-09-22 03:58:53+00:00 | process_start | `service_account_16` → `scheduled_task18` | score 0.33 | Privilege-related activity
### path-059 (score 0.37)
- Time: 2026-09-22 04:37:05+00:00 — 2026-09-22 04:37:05+00:00
- Entities: edr_console3, endpoint_agent_3
- Evidence:
  - `LAT-N-00473` | 2026-09-22 04:37:05+00:00 | network_connection | `endpoint_agent_3` → `edr_console3` | score 0.33 | Privilege-related activity
### path-060 (score 0.37)
- Time: 2026-09-22 05:07:57+00:00 — 2026-09-22 05:07:57+00:00
- Entities: edr_console17, endpoint_agent_17
- Evidence:
  - `LAT-N-00642` | 2026-09-22 05:07:57+00:00 | network_connection | `endpoint_agent_17` → `edr_console17` | score 0.33 | Privilege-related activity
### path-061 (score 0.37)
- Time: 2026-09-22 05:14:44+00:00 — 2026-09-22 05:14:44+00:00
- Entities: edr_console4, endpoint_agent_24
- Evidence:
  - `LAT-N-00192` | 2026-09-22 05:14:44+00:00 | network_connection | `endpoint_agent_24` → `edr_console4` | score 0.33 | Privilege-related activity
### path-062 (score 0.37)
- Time: 2026-09-22 09:05:32+00:00 — 2026-09-22 09:05:32+00:00
- Entities: scheduled_task14, service_account_5
- Evidence:
  - `LAT-N-00087` | 2026-09-22 09:05:32+00:00 | process_start | `service_account_5` → `scheduled_task14` | score 0.33 | Privilege-related activity
### path-063 (score 0.37)
- Time: 2026-09-22 09:30:44+00:00 — 2026-09-22 09:30:44+00:00
- Entities: employee_14, vpn_gateway12
- Evidence:
  - `LAT-N-00700` | 2026-09-22 09:30:44+00:00 | login_success | `employee_14` → `vpn_gateway12` | score 0.33 | Privilege-related activity
### path-064 (score 0.37)
- Time: 2026-09-22 10:58:27+00:00 — 2026-09-22 10:58:27+00:00
- Entities: employee_19, identity_service14
- Evidence:
  - `LAT-N-00704` | 2026-09-22 10:58:27+00:00 | login_success | `employee_19` → `identity_service14` | score 0.33 | Privilege-related activity
### path-065 (score 0.37)
- Time: 2026-09-22 12:02:23+00:00 — 2026-09-22 12:02:23+00:00
- Entities: shared_folder2, user_5
- Evidence:
  - `LAT-N-00504` | 2026-09-22 12:02:23+00:00 | file_read | `user_5` → `shared_folder2` | score 0.33 | Privilege-related activity
### path-066 (score 0.37)
- Time: 2026-09-22 12:36:45+00:00 — 2026-09-22 12:36:45+00:00
- Entities: admin_1, patch_server2
- Evidence:
  - `LAT-N-00667` | 2026-09-22 12:36:45+00:00 | network_connection | `admin_1` → `patch_server2` | score 0.33 | Privilege-related activity
### path-067 (score 0.37)
- Time: 2026-09-22 13:59:06+00:00 — 2026-09-22 13:59:06+00:00
- Entities: shared_folder14, user_13
- Evidence:
  - `LAT-N-00341` | 2026-09-22 13:59:06+00:00 | file_read | `user_13` → `shared_folder14` | score 0.33 | Privilege-related activity
### path-068 (score 0.37)
- Time: 2026-09-22 14:44:16+00:00 — 2026-09-22 14:44:16+00:00
- Entities: host_11, internal_dns6
- Evidence:
  - `LAT-N-00448` | 2026-09-22 14:44:16+00:00 | dns_query | `host_11` → `internal_dns6` | score 0.33 | Privilege-related activity
### path-069 (score 0.37)
- Time: 2026-09-22 15:12:27+00:00 — 2026-09-22 15:12:27+00:00
- Entities: host_3, internal_dns17
- Evidence:
  - `LAT-N-00391` | 2026-09-22 15:12:27+00:00 | dns_query | `host_3` → `internal_dns17` | score 0.33 | Privilege-related activity
### path-070 (score 0.37)
- Time: 2026-09-22 15:27:50+00:00 — 2026-09-22 15:27:50+00:00
- Entities: admin_17, patch_server8
- Evidence:
  - `LAT-N-00064` | 2026-09-22 15:27:50+00:00 | network_connection | `admin_17` → `patch_server8` | score 0.33 | Privilege-related activity
### path-071 (score 0.37)
- Time: 2026-09-22 17:07:56+00:00 — 2026-09-22 17:07:56+00:00
- Entities: admin_7, patch_server7
- Evidence:
  - `LAT-N-00057` | 2026-09-22 17:07:56+00:00 | network_connection | `admin_7` → `patch_server7` | score 0.33 | Privilege-related activity
### path-072 (score 0.37)
- Time: 2026-09-22 19:53:05+00:00 — 2026-09-22 19:53:05+00:00
- Entities: admin_24, patch_server8
- Evidence:
  - `LAT-N-00493` | 2026-09-22 19:53:05+00:00 | network_connection | `admin_24` → `patch_server8` | score 0.33 | Privilege-related activity
### path-073 (score 0.37)
- Time: 2026-09-22 21:14:08+00:00 — 2026-09-22 21:14:08+00:00
- Entities: shared_folder1, user_21
- Evidence:
  - `LAT-N-00679` | 2026-09-22 21:14:08+00:00 | file_read | `user_21` → `shared_folder1` | score 0.33 | Privilege-related activity
### path-074 (score 0.37)
- Time: 2026-09-22 21:24:30+00:00 — 2026-09-22 21:24:30+00:00
- Entities: employee_23, identity_service2
- Evidence:
  - `LAT-N-00015` | 2026-09-22 21:24:30+00:00 | login_success | `employee_23` → `identity_service2` | score 0.33 | Privilege-related activity
### path-075 (score 0.37)
- Time: 2026-09-22 21:53:52+00:00 — 2026-09-22 21:53:52+00:00
- Entities: host_15, internal_dns10
- Evidence:
  - `LAT-N-00632` | 2026-09-22 21:53:52+00:00 | dns_query | `host_15` → `internal_dns10` | score 0.33 | Privilege-related activity
### path-076 (score 0.37)
- Time: 2026-09-22 22:19:32+00:00 — 2026-09-22 22:19:32+00:00
- Entities: admin_17, patch_server15
- Evidence:
  - `LAT-N-00376` | 2026-09-22 22:19:32+00:00 | network_connection | `admin_17` → `patch_server15` | score 0.33 | Privilege-related activity
### path-077 (score 0.37)
- Time: 2026-09-22 22:30:31+00:00 — 2026-09-22 22:30:31+00:00
- Entities: admin_23, patch_server1
- Evidence:
  - `LAT-N-00477` | 2026-09-22 22:30:31+00:00 | network_connection | `admin_23` → `patch_server1` | score 0.33 | Privilege-related activity
### path-078 (score 0.37)
- Time: 2026-09-22 23:17:59+00:00 — 2026-09-22 23:17:59+00:00
- Entities: shared_folder1, user_15
- Evidence:
  - `LAT-N-00375` | 2026-09-22 23:17:59+00:00 | file_read | `user_15` → `shared_folder1` | score 0.33 | Privilege-related activity
### path-079 (score 0.37)
- Time: 2026-09-23 01:03:45+00:00 — 2026-09-23 01:03:45+00:00
- Entities: host_20, internal_dns1
- Evidence:
  - `LAT-N-00026` | 2026-09-23 01:03:45+00:00 | dns_query | `host_20` → `internal_dns1` | score 0.33 | Privilege-related activity
### path-080 (score 0.37)
- Time: 2026-09-23 01:35:24+00:00 — 2026-09-23 01:35:24+00:00
- Entities: admin_15, patch_server11
- Evidence:
  - `LAT-N-00530` | 2026-09-23 01:35:24+00:00 | network_connection | `admin_15` → `patch_server11` | score 0.33 | Privilege-related activity
### path-081 (score 0.37)
- Time: 2026-09-23 02:25:53+00:00 — 2026-09-23 02:25:53+00:00
- Entities: admin_23, patch_server15
- Evidence:
  - `LAT-N-00597` | 2026-09-23 02:25:53+00:00 | network_connection | `admin_23` → `patch_server15` | score 0.33 | Privilege-related activity
### path-082 (score 0.37)
- Time: 2026-09-23 02:28:13+00:00 — 2026-09-23 02:28:13+00:00
- Entities: edr_console17, endpoint_agent_23
- Evidence:
  - `LAT-N-00219` | 2026-09-23 02:28:13+00:00 | network_connection | `endpoint_agent_23` → `edr_console17` | score 0.33 | Privilege-related activity
### path-083 (score 0.37)
- Time: 2026-09-23 03:14:47+00:00 — 2026-09-23 03:14:47+00:00
- Entities: admin_19, patch_server16
- Evidence:
  - `LAT-N-00203` | 2026-09-23 03:14:47+00:00 | network_connection | `admin_19` → `patch_server16` | score 0.33 | Privilege-related activity
### path-084 (score 0.37)
- Time: 2026-09-23 03:16:01+00:00 — 2026-09-23 03:16:01+00:00
- Entities: edr_console7, endpoint_agent_25
- Evidence:
  - `LAT-N-00234` | 2026-09-23 03:16:01+00:00 | network_connection | `endpoint_agent_25` → `edr_console7` | score 0.33 | Privilege-related activity
### path-090 (score 0.37)
- Time: 2026-09-23 04:19:34+00:00 — 2026-09-23 04:19:34+00:00
- Entities: scheduled_task18, service_account_19
- Evidence:
  - `LAT-N-00542` | 2026-09-23 04:19:34+00:00 | process_start | `service_account_19` → `scheduled_task18` | score 0.33 | Privilege-related activity
### path-091 (score 0.37)
- Time: 2026-09-23 04:34:15+00:00 — 2026-09-23 04:34:15+00:00
- Entities: admin_23, patch_server13
- Evidence:
  - `LAT-N-00420` | 2026-09-23 04:34:15+00:00 | network_connection | `admin_23` → `patch_server13` | score 0.33 | Privilege-related activity
### path-092 (score 0.37)
- Time: 2026-09-23 05:03:22+00:00 — 2026-09-23 05:03:22+00:00
- Entities: shared_folder13, user_19
- Evidence:
  - `LAT-N-00245` | 2026-09-23 05:03:22+00:00 | file_read | `user_19` → `shared_folder13` | score 0.33 | Privilege-related activity
### path-093 (score 0.37)
- Time: 2026-09-23 05:05:40+00:00 — 2026-09-23 05:05:40+00:00
- Entities: host_22, internal_dns13
- Evidence:
  - `LAT-N-00382` | 2026-09-23 05:05:40+00:00 | dns_query | `host_22` → `internal_dns13` | score 0.33 | Privilege-related activity
### path-094 (score 0.37)
- Time: 2026-09-23 05:07:17+00:00 — 2026-09-23 05:07:17+00:00
- Entities: host_17, internal_dns16
- Evidence:
  - `LAT-N-00544` | 2026-09-23 05:07:17+00:00 | dns_query | `host_17` → `internal_dns16` | score 0.33 | Privilege-related activity
### path-095 (score 0.37)
- Time: 2026-09-23 06:29:20+00:00 — 2026-09-23 06:29:20+00:00
- Entities: admin_15, patch_server17
- Evidence:
  - `LAT-N-00130` | 2026-09-23 06:29:20+00:00 | network_connection | `admin_15` → `patch_server17` | score 0.33 | Privilege-related activity
### path-096 (score 0.37)
- Time: 2026-09-23 06:52:05+00:00 — 2026-09-23 06:52:05+00:00
- Entities: employee_8, identity_service8
- Evidence:
  - `LAT-N-00427` | 2026-09-23 06:52:05+00:00 | login_success | `employee_8` → `identity_service8` | score 0.33 | Privilege-related activity
### path-097 (score 0.37)
- Time: 2026-09-23 08:09:55+00:00 — 2026-09-23 08:09:55+00:00
- Entities: scheduled_task16, service_account_16
- Evidence:
  - `LAT-N-00479` | 2026-09-23 08:09:55+00:00 | process_start | `service_account_16` → `scheduled_task16` | score 0.33 | Privilege-related activity
### path-098 (score 0.37)
- Time: 2026-09-23 08:34:07+00:00 — 2026-09-23 08:34:07+00:00
- Entities: admin_1, patch_server13
- Evidence:
  - `LAT-N-00554` | 2026-09-23 08:34:07+00:00 | network_connection | `admin_1` → `patch_server13` | score 0.33 | Privilege-related activity
### path-099 (score 0.37)
- Time: 2026-09-23 10:04:20+00:00 — 2026-09-23 10:04:20+00:00
- Entities: employee_1, vpn_gateway5
- Evidence:
  - `LAT-N-00460` | 2026-09-23 10:04:20+00:00 | login_success | `employee_1` → `vpn_gateway5` | score 0.33 | Privilege-related activity
### path-100 (score 0.37)
- Time: 2026-09-23 10:08:09+00:00 — 2026-09-23 10:08:09+00:00
- Entities: admin_23, patch_server17
- Evidence:
  - `LAT-N-00147` | 2026-09-23 10:08:09+00:00 | network_connection | `admin_23` → `patch_server17` | score 0.33 | Privilege-related activity
### path-101 (score 0.37)
- Time: 2026-09-23 10:23:13+00:00 — 2026-09-23 10:23:13+00:00
- Entities: admin_16, patch_server7
- Evidence:
  - `LAT-N-00404` | 2026-09-23 10:23:13+00:00 | network_connection | `admin_16` → `patch_server7` | score 0.33 | Privilege-related activity
### path-102 (score 0.37)
- Time: 2026-09-23 11:33:37+00:00 — 2026-09-23 11:33:37+00:00
- Entities: admin_2, patch_server9
- Evidence:
  - `LAT-N-00474` | 2026-09-23 11:33:37+00:00 | network_connection | `admin_2` → `patch_server9` | score 0.33 | Privilege-related activity
### path-103 (score 0.37)
- Time: 2026-09-23 12:17:14+00:00 — 2026-09-23 12:17:14+00:00
- Entities: admin_3, patch_server17
- Evidence:
  - `LAT-N-00658` | 2026-09-23 12:17:14+00:00 | network_connection | `admin_3` → `patch_server17` | score 0.33 | Privilege-related activity
### path-104 (score 0.37)
- Time: 2026-09-23 13:43:26+00:00 — 2026-09-23 13:43:26+00:00
- Entities: admin_21, patch_server6
- Evidence:
  - `LAT-N-00141` | 2026-09-23 13:43:26+00:00 | network_connection | `admin_21` → `patch_server6` | score 0.33 | Privilege-related activity
### path-105 (score 0.37)
- Time: 2026-09-23 13:47:15+00:00 — 2026-09-23 13:47:15+00:00
- Entities: admin_16, patch_server8
- Evidence:
  - `LAT-N-00516` | 2026-09-23 13:47:15+00:00 | network_connection | `admin_16` → `patch_server8` | score 0.33 | Privilege-related activity
### path-106 (score 0.37)
- Time: 2026-09-23 13:56:21+00:00 — 2026-09-23 13:56:21+00:00
- Entities: admin_3, patch_server7
- Evidence:
  - `LAT-N-00476` | 2026-09-23 13:56:21+00:00 | network_connection | `admin_3` → `patch_server7` | score 0.33 | Privilege-related activity
### path-107 (score 0.37)
- Time: 2026-09-23 14:24:12+00:00 — 2026-09-23 14:24:12+00:00
- Entities: employee_23, vpn_gateway16
- Evidence:
  - `LAT-N-00507` | 2026-09-23 14:24:12+00:00 | login_success | `employee_23` → `vpn_gateway16` | score 0.33 | Privilege-related activity
### path-108 (score 0.37)
- Time: 2026-09-23 16:00:31+00:00 — 2026-09-23 16:00:31+00:00
- Entities: admin_3, patch_server1
- Evidence:
  - `LAT-N-00287` | 2026-09-23 16:00:31+00:00 | network_connection | `admin_3` → `patch_server1` | score 0.33 | Privilege-related activity
### path-109 (score 0.37)
- Time: 2026-09-23 16:47:29+00:00 — 2026-09-23 16:47:29+00:00
- Entities: admin_23, patch_server15
- Evidence:
  - `LAT-N-00286` | 2026-09-23 16:47:29+00:00 | network_connection | `admin_23` → `patch_server15` | score 0.33 | Privilege-related activity
### path-110 (score 0.37)
- Time: 2026-09-23 16:53:50+00:00 — 2026-09-23 16:53:50+00:00
- Entities: admin_16, patch_server4
- Evidence:
  - `LAT-N-00594` | 2026-09-23 16:53:50+00:00 | network_connection | `admin_16` → `patch_server4` | score 0.33 | Privilege-related activity
### path-111 (score 0.37)
- Time: 2026-09-23 17:18:51+00:00 — 2026-09-23 17:18:51+00:00
- Entities: admin_2, patch_server15
- Evidence:
  - `LAT-N-00117` | 2026-09-23 17:18:51+00:00 | network_connection | `admin_2` → `patch_server15` | score 0.33 | Privilege-related activity
### path-112 (score 0.37)
- Time: 2026-09-23 17:25:37+00:00 — 2026-09-23 17:25:37+00:00
- Entities: edr_console9, endpoint_agent_18
- Evidence:
  - `LAT-N-00561` | 2026-09-23 17:25:37+00:00 | network_connection | `endpoint_agent_18` → `edr_console9` | score 0.33 | Privilege-related activity
### path-113 (score 0.37)
- Time: 2026-09-23 18:16:15+00:00 — 2026-09-23 18:16:15+00:00
- Entities: employee_19, identity_service4
- Evidence:
  - `LAT-N-00681` | 2026-09-23 18:16:15+00:00 | login_success | `employee_19` → `identity_service4` | score 0.33 | Privilege-related activity
### path-114 (score 0.37)
- Time: 2026-09-23 18:22:44+00:00 — 2026-09-23 18:22:44+00:00
- Entities: admin_7, patch_server4
- Evidence:
  - `LAT-N-00132` | 2026-09-23 18:22:44+00:00 | network_connection | `admin_7` → `patch_server4` | score 0.33 | Privilege-related activity
### path-115 (score 0.37)
- Time: 2026-09-23 18:57:45+00:00 — 2026-09-23 18:57:45+00:00
- Entities: host_3, internal_dns12
- Evidence:
  - `LAT-N-00584` | 2026-09-23 18:57:45+00:00 | dns_query | `host_3` → `internal_dns12` | score 0.33 | Privilege-related activity
### path-116 (score 0.37)
- Time: 2026-09-23 19:08:18+00:00 — 2026-09-23 19:08:18+00:00
- Entities: admin_12, patch_server18
- Evidence:
  - `LAT-N-00215` | 2026-09-23 19:08:18+00:00 | network_connection | `admin_12` → `patch_server18` | score 0.33 | Privilege-related activity
### path-117 (score 0.37)
- Time: 2026-09-23 19:34:27+00:00 — 2026-09-23 19:34:27+00:00
- Entities: admin_3, patch_server14
- Evidence:
  - `LAT-N-00595` | 2026-09-23 19:34:27+00:00 | network_connection | `admin_3` → `patch_server14` | score 0.33 | Privilege-related activity
### path-118 (score 0.37)
- Time: 2026-09-23 19:51:03+00:00 — 2026-09-23 19:51:03+00:00
- Entities: admin_16, patch_server8
- Evidence:
  - `LAT-N-00050` | 2026-09-23 19:51:03+00:00 | network_connection | `admin_16` → `patch_server8` | score 0.33 | Privilege-related activity
### path-119 (score 0.37)
- Time: 2026-09-23 20:39:56+00:00 — 2026-09-23 20:39:56+00:00
- Entities: admin_1, patch_server12
- Evidence:
  - `LAT-N-00625` | 2026-09-23 20:39:56+00:00 | network_connection | `admin_1` → `patch_server12` | score 0.33 | Privilege-related activity
### path-120 (score 0.37)
- Time: 2026-09-23 22:23:27+00:00 — 2026-09-23 22:23:27+00:00
- Entities: admin_20, patch_server9
- Evidence:
  - `LAT-N-00034` | 2026-09-23 22:23:27+00:00 | network_connection | `admin_20` → `patch_server9` | score 0.33 | Privilege-related activity
### path-121 (score 0.37)
- Time: 2026-09-23 22:25:48+00:00 — 2026-09-23 22:25:48+00:00
- Entities: employee_23, vpn_gateway12
- Evidence:
  - `LAT-N-00592` | 2026-09-23 22:25:48+00:00 | login_success | `employee_23` → `vpn_gateway12` | score 0.33 | Privilege-related activity
### path-122 (score 0.37)
- Time: 2026-09-23 22:57:35+00:00 — 2026-09-23 22:57:35+00:00
- Entities: admin_2, patch_server15
- Evidence:
  - `LAT-N-00354` | 2026-09-23 22:57:35+00:00 | network_connection | `admin_2` → `patch_server15` | score 0.33 | Privilege-related activity
### path-123 (score 0.37)
- Time: 2026-09-23 23:07:36+00:00 — 2026-09-23 23:07:36+00:00
- Entities: employee_19, identity_service13
- Evidence:
  - `LAT-N-00248` | 2026-09-23 23:07:36+00:00 | login_success | `employee_19` → `identity_service13` | score 0.33 | Privilege-related activity
### path-124 (score 0.37)
- Time: 2026-09-23 23:24:34+00:00 — 2026-09-23 23:24:34+00:00
- Entities: scheduled_task1, service_account_11
- Evidence:
  - `LAT-N-00313` | 2026-09-23 23:24:34+00:00 | process_start | `service_account_11` → `scheduled_task1` | score 0.33 | Privilege-related activity
### path-125 (score 0.37)
- Time: 2026-09-24 01:43:35+00:00 — 2026-09-24 01:43:35+00:00
- Entities: admin_16, patch_server16
- Evidence:
  - `LAT-N-00385` | 2026-09-24 01:43:35+00:00 | network_connection | `admin_16` → `patch_server16` | score 0.33 | Privilege-related activity
### path-126 (score 0.37)
- Time: 2026-09-24 02:39:30+00:00 — 2026-09-24 02:39:30+00:00
- Entities: employee_21, identity_service2
- Evidence:
  - `LAT-N-00624` | 2026-09-24 02:39:30+00:00 | login_success | `employee_21` → `identity_service2` | score 0.33 | Privilege-related activity
### path-127 (score 0.37)
- Time: 2026-09-24 02:47:52+00:00 — 2026-09-24 02:47:52+00:00
- Entities: scheduled_task12, service_account_22
- Evidence:
  - `LAT-N-00534` | 2026-09-24 02:47:52+00:00 | process_start | `service_account_22` → `scheduled_task12` | score 0.33 | Privilege-related activity
### path-128 (score 0.37)
- Time: 2026-09-24 03:22:43+00:00 — 2026-09-24 03:22:43+00:00
- Entities: admin_4, patch_server4
- Evidence:
  - `LAT-N-00511` | 2026-09-24 03:22:43+00:00 | network_connection | `admin_4` → `patch_server4` | score 0.33 | Privilege-related activity
### path-129 (score 0.37)
- Time: 2026-09-24 04:37:34+00:00 — 2026-09-24 04:37:34+00:00
- Entities: host_20, internal_dns2
- Evidence:
  - `LAT-N-00393` | 2026-09-24 04:37:34+00:00 | dns_query | `host_20` → `internal_dns2` | score 0.33 | Privilege-related activity
### path-130 (score 0.37)
- Time: 2026-09-24 06:53:42+00:00 — 2026-09-24 06:53:42+00:00
- Entities: employee_24, identity_service11
- Evidence:
  - `LAT-N-00300` | 2026-09-24 06:53:42+00:00 | login_success | `employee_24` → `identity_service11` | score 0.33 | Privilege-related activity
### path-131 (score 0.37)
- Time: 2026-09-24 07:26:38+00:00 — 2026-09-24 07:26:38+00:00
- Entities: admin_5, patch_server4
- Evidence:
  - `LAT-N-00067` | 2026-09-24 07:26:38+00:00 | network_connection | `admin_5` → `patch_server4` | score 0.33 | Privilege-related activity
### path-132 (score 0.37)
- Time: 2026-09-24 07:56:13+00:00 — 2026-09-24 07:56:13+00:00
- Entities: admin_25, patch_server6
- Evidence:
  - `LAT-N-00384` | 2026-09-24 07:56:13+00:00 | network_connection | `admin_25` → `patch_server6` | score 0.33 | Privilege-related activity
### path-133 (score 0.37)
- Time: 2026-09-24 08:44:51+00:00 — 2026-09-24 08:44:51+00:00
- Entities: shared_folder17, user_5
- Evidence:
  - `LAT-N-00153` | 2026-09-24 08:44:51+00:00 | file_read | `user_5` → `shared_folder17` | score 0.33 | Privilege-related activity
### path-134 (score 0.37)
- Time: 2026-09-24 09:22:32+00:00 — 2026-09-24 09:22:32+00:00
- Entities: admin_16, patch_server8
- Evidence:
  - `LAT-N-00484` | 2026-09-24 09:22:32+00:00 | network_connection | `admin_16` → `patch_server8` | score 0.33 | Privilege-related activity
### path-135 (score 0.37)
- Time: 2026-09-24 10:54:25+00:00 — 2026-09-24 10:54:25+00:00
- Entities: host_11, internal_dns15
- Evidence:
  - `LAT-N-00525` | 2026-09-24 10:54:25+00:00 | dns_query | `host_11` → `internal_dns15` | score 0.33 | Privilege-related activity
### path-136 (score 0.37)
- Time: 2026-09-24 11:22:01+00:00 — 2026-09-24 11:22:01+00:00
- Entities: admin_13, patch_server11
- Evidence:
  - `LAT-N-00609` | 2026-09-24 11:22:01+00:00 | network_connection | `admin_13` → `patch_server11` | score 0.33 | Privilege-related activity
### path-137 (score 0.37)
- Time: 2026-09-24 11:59:22+00:00 — 2026-09-24 11:59:22+00:00
- Entities: host_21, internal_dns5
- Evidence:
  - `LAT-N-00488` | 2026-09-24 11:59:22+00:00 | dns_query | `host_21` → `internal_dns5` | score 0.33 | Privilege-related activity
### path-138 (score 0.37)
- Time: 2026-09-24 12:42:04+00:00 — 2026-09-24 12:42:04+00:00
- Entities: employee_13, identity_service10
- Evidence:
  - `LAT-N-00687` | 2026-09-24 12:42:04+00:00 | login_success | `employee_13` → `identity_service10` | score 0.33 | Privilege-related activity
### path-139 (score 0.37)
- Time: 2026-09-24 13:11:06+00:00 — 2026-09-24 13:11:06+00:00
- Entities: admin_18, patch_server6
- Evidence:
  - `LAT-N-00301` | 2026-09-24 13:11:06+00:00 | network_connection | `admin_18` → `patch_server6` | score 0.33 | Privilege-related activity
### path-140 (score 0.37)
- Time: 2026-09-24 14:28:58+00:00 — 2026-09-24 14:28:58+00:00
- Entities: employee_3, identity_service17
- Evidence:
  - `LAT-N-00707` | 2026-09-24 14:28:58+00:00 | login_success | `employee_3` → `identity_service17` | score 0.33 | Privilege-related activity
### path-141 (score 0.37)
- Time: 2026-09-24 15:11:07+00:00 — 2026-09-24 15:11:07+00:00
- Entities: employee_20, identity_service13
- Evidence:
  - `LAT-N-00314` | 2026-09-24 15:11:07+00:00 | login_success | `employee_20` → `identity_service13` | score 0.33 | Privilege-related activity
### path-142 (score 0.37)
- Time: 2026-09-24 16:03:16+00:00 — 2026-09-24 16:03:16+00:00
- Entities: admin_2, patch_server5
- Evidence:
  - `LAT-N-00220` | 2026-09-24 16:03:16+00:00 | network_connection | `admin_2` → `patch_server5` | score 0.33 | Privilege-related activity
### path-143 (score 0.37)
- Time: 2026-09-24 16:03:36+00:00 — 2026-09-24 16:03:36+00:00
- Entities: employee_3, vpn_gateway13
- Evidence:
  - `LAT-N-00007` | 2026-09-24 16:03:36+00:00 | login_success | `employee_3` → `vpn_gateway13` | score 0.33 | Privilege-related activity
### path-144 (score 0.37)
- Time: 2026-09-24 16:57:27+00:00 — 2026-09-24 16:57:27+00:00
- Entities: host_19, internal_dns4
- Evidence:
  - `LAT-N-00199` | 2026-09-24 16:57:27+00:00 | dns_query | `host_19` → `internal_dns4` | score 0.33 | Privilege-related activity
### path-145 (score 0.37)
- Time: 2026-09-24 18:01:30+00:00 — 2026-09-24 18:01:30+00:00
- Entities: shared_folder2, user_2
- Evidence:
  - `LAT-N-00281` | 2026-09-24 18:01:30+00:00 | file_read | `user_2` → `shared_folder2` | score 0.33 | Privilege-related activity
### path-146 (score 0.37)
- Time: 2026-09-24 18:06:43+00:00 — 2026-09-24 18:06:43+00:00
- Entities: shared_folder13, user_11
- Evidence:
  - `LAT-N-00293` | 2026-09-24 18:06:43+00:00 | file_read | `user_11` → `shared_folder13` | score 0.33 | Privilege-related activity
### path-147 (score 0.37)
- Time: 2026-09-24 18:20:35+00:00 — 2026-09-24 18:20:35+00:00
- Entities: host_11, internal_dns8
- Evidence:
  - `LAT-N-00591` | 2026-09-24 18:20:35+00:00 | dns_query | `host_11` → `internal_dns8` | score 0.33 | Privilege-related activity
### path-148 (score 0.37)
- Time: 2026-09-24 18:32:43+00:00 — 2026-09-24 18:32:43+00:00
- Entities: admin_8, patch_server3
- Evidence:
  - `LAT-N-00565` | 2026-09-24 18:32:43+00:00 | network_connection | `admin_8` → `patch_server3` | score 0.33 | Privilege-related activity
### path-149 (score 0.37)
- Time: 2026-09-24 19:52:31+00:00 — 2026-09-24 19:52:31+00:00
- Entities: shared_folder6, user_5
- Evidence:
  - `LAT-N-00180` | 2026-09-24 19:52:31+00:00 | file_read | `user_5` → `shared_folder6` | score 0.33 | Privilege-related activity
### path-150 (score 0.37)
- Time: 2026-09-24 22:24:00+00:00 — 2026-09-24 22:24:00+00:00
- Entities: edr_console17, endpoint_agent_10
- Evidence:
  - `LAT-N-00695` | 2026-09-24 22:24:00+00:00 | network_connection | `endpoint_agent_10` → `edr_console17` | score 0.33 | Privilege-related activity
### path-151 (score 0.37)
- Time: 2026-09-24 23:23:45+00:00 — 2026-09-24 23:23:45+00:00
- Entities: admin_2, patch_server16
- Evidence:
  - `LAT-N-00655` | 2026-09-24 23:23:45+00:00 | network_connection | `admin_2` → `patch_server16` | score 0.33 | Privilege-related activity
### path-152 (score 0.37)
- Time: 2026-09-25 00:34:42+00:00 — 2026-09-25 00:34:42+00:00
- Entities: admin_16, patch_server12
- Evidence:
  - `LAT-N-00660` | 2026-09-25 00:34:42+00:00 | network_connection | `admin_16` → `patch_server12` | score 0.33 | Privilege-related activity
### path-153 (score 0.37)
- Time: 2026-09-25 01:12:06+00:00 — 2026-09-25 01:12:06+00:00
- Entities: shared_folder8, user_1
- Evidence:
  - `LAT-N-00178` | 2026-09-25 01:12:06+00:00 | file_read | `user_1` → `shared_folder8` | score 0.33 | Privilege-related activity
### path-154 (score 0.37)
- Time: 2026-09-25 01:25:27+00:00 — 2026-09-25 01:25:27+00:00
- Entities: shared_folder7, user_9
- Evidence:
  - `LAT-N-00654` | 2026-09-25 01:25:27+00:00 | file_read | `user_9` → `shared_folder7` | score 0.33 | Privilege-related activity
### path-155 (score 0.37)
- Time: 2026-09-25 01:55:11+00:00 — 2026-09-25 01:55:11+00:00
- Entities: host_19, internal_dns7
- Evidence:
  - `LAT-N-00237` | 2026-09-25 01:55:11+00:00 | dns_query | `host_19` → `internal_dns7` | score 0.33 | Privilege-related activity
### path-156 (score 0.37)
- Time: 2026-09-25 02:30:27+00:00 — 2026-09-25 02:30:27+00:00
- Entities: admin_25, patch_server7
- Evidence:
  - `LAT-N-00417` | 2026-09-25 02:30:27+00:00 | network_connection | `admin_25` → `patch_server7` | score 0.33 | Privilege-related activity
### path-157 (score 0.37)
- Time: 2026-09-25 03:14:44+00:00 — 2026-09-25 03:14:44+00:00
- Entities: shared_folder14, user_20
- Evidence:
  - `LAT-N-00500` | 2026-09-25 03:14:44+00:00 | file_read | `user_20` → `shared_folder14` | score 0.33 | Privilege-related activity
### path-158 (score 0.37)
- Time: 2026-09-25 04:24:08+00:00 — 2026-09-25 04:24:08+00:00
- Entities: admin_4, patch_server13
- Evidence:
  - `LAT-N-00684` | 2026-09-25 04:24:08+00:00 | network_connection | `admin_4` → `patch_server13` | score 0.33 | Privilege-related activity
### path-159 (score 0.37)
- Time: 2026-09-25 04:37:48+00:00 — 2026-09-25 04:37:48+00:00
- Entities: admin_15, patch_server15
- Evidence:
  - `LAT-N-00577` | 2026-09-25 04:37:48+00:00 | network_connection | `admin_15` → `patch_server15` | score 0.33 | Privilege-related activity
### path-160 (score 0.37)
- Time: 2026-09-25 04:42:42+00:00 — 2026-09-25 04:42:42+00:00
- Entities: scheduled_task7, service_account_12
- Evidence:
  - `LAT-N-00113` | 2026-09-25 04:42:42+00:00 | process_start | `service_account_12` → `scheduled_task7` | score 0.33 | Privilege-related activity
### path-161 (score 0.37)
- Time: 2026-09-25 06:30:21+00:00 — 2026-09-25 06:30:21+00:00
- Entities: scheduled_task15, service_account_8
- Evidence:
  - `LAT-N-00221` | 2026-09-25 06:30:21+00:00 | process_start | `service_account_8` → `scheduled_task15` | score 0.33 | Privilege-related activity
### path-162 (score 0.37)
- Time: 2026-09-25 07:14:33+00:00 — 2026-09-25 07:14:33+00:00
- Entities: admin_11, patch_server9
- Evidence:
  - `LAT-N-00253` | 2026-09-25 07:14:33+00:00 | network_connection | `admin_11` → `patch_server9` | score 0.33 | Privilege-related activity
### path-163 (score 0.37)
- Time: 2026-09-25 07:19:28+00:00 — 2026-09-25 07:19:28+00:00
- Entities: edr_console6, endpoint_agent_25
- Evidence:
  - `LAT-N-00702` | 2026-09-25 07:19:28+00:00 | network_connection | `endpoint_agent_25` → `edr_console6` | score 0.33 | Privilege-related activity
### path-164 (score 0.37)
- Time: 2026-09-25 08:25:15+00:00 — 2026-09-25 08:25:15+00:00
- Entities: scheduled_task17, service_account_15
- Evidence:
  - `LAT-N-00690` | 2026-09-25 08:25:15+00:00 | process_start | `service_account_15` → `scheduled_task17` | score 0.33 | Privilege-related activity
### path-165 (score 0.37)
- Time: 2026-09-25 09:36:58+00:00 — 2026-09-25 09:36:58+00:00
- Entities: admin_12, patch_server12
- Evidence:
  - `LAT-N-00323` | 2026-09-25 09:36:58+00:00 | network_connection | `admin_12` → `patch_server12` | score 0.33 | Privilege-related activity
### path-166 (score 0.37)
- Time: 2026-09-25 10:28:00+00:00 — 2026-09-25 10:28:00+00:00
- Entities: edr_console10, endpoint_agent_16
- Evidence:
  - `LAT-N-00075` | 2026-09-25 10:28:00+00:00 | network_connection | `endpoint_agent_16` → `edr_console10` | score 0.33 | Privilege-related activity
### path-167 (score 0.37)
- Time: 2026-09-25 12:05:51+00:00 — 2026-09-25 12:05:51+00:00
- Entities: edr_console18, endpoint_agent_13
- Evidence:
  - `LAT-N-00368` | 2026-09-25 12:05:51+00:00 | network_connection | `endpoint_agent_13` → `edr_console18` | score 0.33 | Privilege-related activity
### path-168 (score 0.37)
- Time: 2026-09-25 12:25:02+00:00 — 2026-09-25 12:25:02+00:00
- Entities: scheduled_task6, service_account_4
- Evidence:
  - `LAT-N-00019` | 2026-09-25 12:25:02+00:00 | process_start | `service_account_4` → `scheduled_task6` | score 0.33 | Privilege-related activity
### path-169 (score 0.37)
- Time: 2026-09-25 12:28:58+00:00 — 2026-09-25 12:28:58+00:00
- Entities: employee_2, identity_service13
- Evidence:
  - `LAT-N-00206` | 2026-09-25 12:28:58+00:00 | login_success | `employee_2` → `identity_service13` | score 0.33 | Privilege-related activity
### path-170 (score 0.37)
- Time: 2026-09-25 12:44:19+00:00 — 2026-09-25 12:44:19+00:00
- Entities: employee_17, identity_service12
- Evidence:
  - `LAT-N-00618` | 2026-09-25 12:44:19+00:00 | login_success | `employee_17` → `identity_service12` | score 0.33 | Privilege-related activity
### path-171 (score 0.37)
- Time: 2026-09-25 13:14:06+00:00 — 2026-09-25 13:14:06+00:00
- Entities: admin_16, patch_server6
- Evidence:
  - `LAT-N-00226` | 2026-09-25 13:14:06+00:00 | network_connection | `admin_16` → `patch_server6` | score 0.33 | Privilege-related activity
### path-172 (score 0.37)
- Time: 2026-09-25 13:38:28+00:00 — 2026-09-25 13:38:28+00:00
- Entities: admin_18, patch_server14
- Evidence:
  - `LAT-N-00302` | 2026-09-25 13:38:28+00:00 | network_connection | `admin_18` → `patch_server14` | score 0.33 | Privilege-related activity
### path-173 (score 0.37)
- Time: 2026-09-25 14:00:37+00:00 — 2026-09-25 14:00:37+00:00
- Entities: employee_23, identity_service5
- Evidence:
  - `LAT-N-00029` | 2026-09-25 14:00:37+00:00 | login_success | `employee_23` → `identity_service5` | score 0.33 | Privilege-related activity
### path-174 (score 0.37)
- Time: 2026-09-25 15:15:49+00:00 — 2026-09-25 15:15:49+00:00
- Entities: employee_18, vpn_gateway6
- Evidence:
  - `LAT-N-00518` | 2026-09-25 15:15:49+00:00 | login_success | `employee_18` → `vpn_gateway6` | score 0.33 | Privilege-related activity
### path-175 (score 0.37)
- Time: 2026-09-25 15:16:29+00:00 — 2026-09-25 15:16:29+00:00
- Entities: shared_folder3, user_15
- Evidence:
  - `LAT-N-00109` | 2026-09-25 15:16:29+00:00 | file_read | `user_15` → `shared_folder3` | score 0.33 | Privilege-related activity
### path-176 (score 0.37)
- Time: 2026-09-25 15:34:07+00:00 — 2026-09-25 15:34:07+00:00
- Entities: host_13, internal_dns10
- Evidence:
  - `LAT-N-00310` | 2026-09-25 15:34:07+00:00 | dns_query | `host_13` → `internal_dns10` | score 0.33 | Privilege-related activity
### path-177 (score 0.37)
- Time: 2026-09-25 18:15:42+00:00 — 2026-09-25 18:15:42+00:00
- Entities: admin_15, patch_server11
- Evidence:
  - `LAT-N-00111` | 2026-09-25 18:15:42+00:00 | network_connection | `admin_15` → `patch_server11` | score 0.33 | Privilege-related activity
### path-178 (score 0.37)
- Time: 2026-09-25 18:35:51+00:00 — 2026-09-25 18:35:51+00:00
- Entities: admin_7, patch_server13
- Evidence:
  - `LAT-N-00426` | 2026-09-25 18:35:51+00:00 | network_connection | `admin_7` → `patch_server13` | score 0.33 | Privilege-related activity
### path-179 (score 0.37)
- Time: 2026-09-25 18:57:29+00:00 — 2026-09-25 18:57:29+00:00
- Entities: admin_13, patch_server15
- Evidence:
  - `LAT-N-00059` | 2026-09-25 18:57:29+00:00 | network_connection | `admin_13` → `patch_server15` | score 0.33 | Privilege-related activity
### path-180 (score 0.37)
- Time: 2026-09-25 19:57:50+00:00 — 2026-09-25 19:57:50+00:00
- Entities: admin_4, patch_server13
- Evidence:
  - `LAT-N-00374` | 2026-09-25 19:57:50+00:00 | network_connection | `admin_4` → `patch_server13` | score 0.33 | Privilege-related activity
### path-181 (score 0.37)
- Time: 2026-09-25 20:33:37+00:00 — 2026-09-25 20:33:37+00:00
- Entities: admin_17, patch_server16
- Evidence:
  - `LAT-N-00629` | 2026-09-25 20:33:37+00:00 | network_connection | `admin_17` → `patch_server16` | score 0.33 | Privilege-related activity
### path-182 (score 0.37)
- Time: 2026-09-25 21:35:01+00:00 — 2026-09-25 21:35:01+00:00
- Entities: admin_2, patch_server5
- Evidence:
  - `LAT-N-00025` | 2026-09-25 21:35:01+00:00 | network_connection | `admin_2` → `patch_server5` | score 0.33 | Privilege-related activity
### path-183 (score 0.37)
- Time: 2026-09-25 21:54:17+00:00 — 2026-09-25 21:54:17+00:00
- Entities: shared_folder17, user_12
- Evidence:
  - `LAT-N-00230` | 2026-09-25 21:54:17+00:00 | file_read | `user_12` → `shared_folder17` | score 0.33 | Privilege-related activity
### path-184 (score 0.37)
- Time: 2026-09-25 22:52:28+00:00 — 2026-09-25 22:52:28+00:00
- Entities: admin_13, patch_server3
- Evidence:
  - `LAT-N-00114` | 2026-09-25 22:52:28+00:00 | network_connection | `admin_13` → `patch_server3` | score 0.33 | Privilege-related activity
### path-185 (score 0.37)
- Time: 2026-09-26 00:03:48+00:00 — 2026-09-26 00:03:48+00:00
- Entities: employee_4, identity_service15
- Evidence:
  - `LAT-N-00366` | 2026-09-26 00:03:48+00:00 | login_success | `employee_4` → `identity_service15` | score 0.33 | Privilege-related activity
### path-186 (score 0.37)
- Time: 2026-09-26 01:31:23+00:00 — 2026-09-26 01:31:23+00:00
- Entities: admin_1, patch_server15
- Evidence:
  - `LAT-N-00503` | 2026-09-26 01:31:23+00:00 | network_connection | `admin_1` → `patch_server15` | score 0.33 | Privilege-related activity
### path-187 (score 0.37)
- Time: 2026-09-26 02:53:40+00:00 — 2026-09-26 02:53:40+00:00
- Entities: edr_console9, endpoint_agent_2
- Evidence:
  - `LAT-N-00177` | 2026-09-26 02:53:40+00:00 | network_connection | `endpoint_agent_2` → `edr_console9` | score 0.33 | Privilege-related activity
### path-188 (score 0.37)
- Time: 2026-09-26 03:28:51+00:00 — 2026-09-26 03:28:51+00:00
- Entities: shared_folder18, user_20
- Evidence:
  - `LAT-N-00166` | 2026-09-26 03:28:51+00:00 | file_read | `user_20` → `shared_folder18` | score 0.33 | Privilege-related activity
### path-189 (score 0.37)
- Time: 2026-09-26 03:33:54+00:00 — 2026-09-26 03:33:54+00:00
- Entities: scheduled_task13, service_account_25
- Evidence:
  - `LAT-N-00328` | 2026-09-26 03:33:54+00:00 | process_start | `service_account_25` → `scheduled_task13` | score 0.33 | Privilege-related activity
### path-190 (score 0.37)
- Time: 2026-09-26 04:30:41+00:00 — 2026-09-26 04:30:41+00:00
- Entities: admin_15, patch_server11
- Evidence:
  - `LAT-N-00689` | 2026-09-26 04:30:41+00:00 | network_connection | `admin_15` → `patch_server11` | score 0.33 | Privilege-related activity
### path-191 (score 0.37)
- Time: 2026-09-26 05:16:06+00:00 — 2026-09-26 05:16:06+00:00
- Entities: admin_5, patch_server3
- Evidence:
  - `LAT-N-00260` | 2026-09-26 05:16:06+00:00 | network_connection | `admin_5` → `patch_server3` | score 0.33 | Privilege-related activity
### path-192 (score 0.37)
- Time: 2026-09-26 07:41:51+00:00 — 2026-09-26 07:41:51+00:00
- Entities: admin_19, patch_server2
- Evidence:
  - `LAT-N-00210` | 2026-09-26 07:41:51+00:00 | network_connection | `admin_19` → `patch_server2` | score 0.33 | Privilege-related activity
### path-193 (score 0.37)
- Time: 2026-09-26 08:05:38+00:00 — 2026-09-26 08:05:38+00:00
- Entities: host_22, internal_dns5
- Evidence:
  - `LAT-N-00519` | 2026-09-26 08:05:38+00:00 | dns_query | `host_22` → `internal_dns5` | score 0.33 | Privilege-related activity
### path-194 (score 0.37)
- Time: 2026-09-26 08:05:44+00:00 — 2026-09-26 08:05:44+00:00
- Entities: host_21, internal_dns11
- Evidence:
  - `LAT-N-00336` | 2026-09-26 08:05:44+00:00 | dns_query | `host_21` → `internal_dns11` | score 0.33 | Privilege-related activity
### path-195 (score 0.37)
- Time: 2026-09-26 08:05:59+00:00 — 2026-09-26 08:05:59+00:00
- Entities: admin_12, patch_server2
- Evidence:
  - `LAT-N-00657` | 2026-09-26 08:05:59+00:00 | network_connection | `admin_12` → `patch_server2` | score 0.33 | Privilege-related activity
### path-196 (score 0.37)
- Time: 2026-09-26 09:40:52+00:00 — 2026-09-26 09:40:52+00:00
- Entities: admin_13, patch_server15
- Evidence:
  - `LAT-N-00456` | 2026-09-26 09:40:52+00:00 | network_connection | `admin_13` → `patch_server15` | score 0.33 | Privilege-related activity
### path-197 (score 0.37)
- Time: 2026-09-26 10:05:46+00:00 — 2026-09-26 10:05:46+00:00
- Entities: admin_20, patch_server18
- Evidence:
  - `LAT-N-00164` | 2026-09-26 10:05:46+00:00 | network_connection | `admin_20` → `patch_server18` | score 0.33 | Privilege-related activity
### path-198 (score 0.37)
- Time: 2026-09-26 10:18:35+00:00 — 2026-09-26 10:18:35+00:00
- Entities: employee_12, vpn_gateway4
- Evidence:
  - `LAT-N-00468` | 2026-09-26 10:18:35+00:00 | login_success | `employee_12` → `vpn_gateway4` | score 0.33 | Privilege-related activity
### path-199 (score 0.37)
- Time: 2026-09-26 11:09:54+00:00 — 2026-09-26 11:09:54+00:00
- Entities: host_15, internal_dns9
- Evidence:
  - `LAT-N-00438` | 2026-09-26 11:09:54+00:00 | dns_query | `host_15` → `internal_dns9` | score 0.33 | Privilege-related activity
### path-200 (score 0.37)
- Time: 2026-09-26 11:11:18+00:00 — 2026-09-26 11:11:18+00:00
- Entities: employee_11, vpn_gateway1
- Evidence:
  - `LAT-N-00155` | 2026-09-26 11:11:18+00:00 | login_success | `employee_11` → `vpn_gateway1` | score 0.33 | Privilege-related activity
### path-201 (score 0.37)
- Time: 2026-09-26 11:56:33+00:00 — 2026-09-26 11:56:33+00:00
- Entities: employee_2, vpn_gateway13
- Evidence:
  - `LAT-N-00181` | 2026-09-26 11:56:33+00:00 | login_success | `employee_2` → `vpn_gateway13` | score 0.33 | Privilege-related activity
### path-202 (score 0.37)
- Time: 2026-09-26 13:01:08+00:00 — 2026-09-26 13:01:08+00:00
- Entities: admin_22, patch_server12
- Evidence:
  - `LAT-N-00659` | 2026-09-26 13:01:08+00:00 | network_connection | `admin_22` → `patch_server12` | score 0.33 | Privilege-related activity
### path-203 (score 0.37)
- Time: 2026-09-26 13:04:10+00:00 — 2026-09-26 13:04:10+00:00
- Entities: admin_17, patch_server5
- Evidence:
  - `LAT-N-00603` | 2026-09-26 13:04:10+00:00 | network_connection | `admin_17` → `patch_server5` | score 0.33 | Privilege-related activity
### path-204 (score 0.37)
- Time: 2026-09-26 15:06:39+00:00 — 2026-09-26 15:06:39+00:00
- Entities: admin_19, patch_server16
- Evidence:
  - `LAT-N-00139` | 2026-09-26 15:06:39+00:00 | network_connection | `admin_19` → `patch_server16` | score 0.33 | Privilege-related activity
### path-205 (score 0.37)
- Time: 2026-09-26 15:24:32+00:00 — 2026-09-26 15:24:32+00:00
- Entities: admin_11, patch_server6
- Evidence:
  - `LAT-N-00332` | 2026-09-26 15:24:32+00:00 | network_connection | `admin_11` → `patch_server6` | score 0.33 | Privilege-related activity
### path-206 (score 0.37)
- Time: 2026-09-26 15:59:16+00:00 — 2026-09-26 15:59:16+00:00
- Entities: employee_24, identity_service3
- Evidence:
  - `LAT-N-00204` | 2026-09-26 15:59:16+00:00 | login_success | `employee_24` → `identity_service3` | score 0.33 | Privilege-related activity
### path-207 (score 0.37)
- Time: 2026-09-26 16:03:06+00:00 — 2026-09-26 16:03:06+00:00
- Entities: admin_23, patch_server9
- Evidence:
  - `LAT-N-00144` | 2026-09-26 16:03:06+00:00 | network_connection | `admin_23` → `patch_server9` | score 0.33 | Privilege-related activity
### path-208 (score 0.37)
- Time: 2026-09-26 16:35:29+00:00 — 2026-09-26 16:35:29+00:00
- Entities: admin_1, patch_server10
- Evidence:
  - `LAT-N-00643` | 2026-09-26 16:35:29+00:00 | network_connection | `admin_1` → `patch_server10` | score 0.33 | Privilege-related activity
### path-209 (score 0.37)
- Time: 2026-09-26 16:44:23+00:00 — 2026-09-26 16:44:23+00:00
- Entities: admin_15, patch_server9
- Evidence:
  - `LAT-N-00108` | 2026-09-26 16:44:23+00:00 | network_connection | `admin_15` → `patch_server9` | score 0.33 | Privilege-related activity
### path-210 (score 0.37)
- Time: 2026-09-26 17:14:42+00:00 — 2026-09-26 17:14:42+00:00
- Entities: admin_6, patch_server6
- Evidence:
  - `LAT-N-00196` | 2026-09-26 17:14:42+00:00 | network_connection | `admin_6` → `patch_server6` | score 0.33 | Privilege-related activity
### path-211 (score 0.37)
- Time: 2026-09-26 17:37:01+00:00 — 2026-09-26 17:37:01+00:00
- Entities: edr_console12, endpoint_agent_20
- Evidence:
  - `LAT-N-00276` | 2026-09-26 17:37:01+00:00 | network_connection | `endpoint_agent_20` → `edr_console12` | score 0.33 | Privilege-related activity
### path-212 (score 0.37)
- Time: 2026-09-26 17:44:49+00:00 — 2026-09-26 17:44:49+00:00
- Entities: admin_2, patch_server18
- Evidence:
  - `LAT-N-00123` | 2026-09-26 17:44:49+00:00 | network_connection | `admin_2` → `patch_server18` | score 0.33 | Privilege-related activity
### path-213 (score 0.37)
- Time: 2026-09-26 17:59:45+00:00 — 2026-09-26 17:59:45+00:00
- Entities: host_18, internal_dns6
- Evidence:
  - `LAT-N-00240` | 2026-09-26 17:59:45+00:00 | dns_query | `host_18` → `internal_dns6` | score 0.33 | Privilege-related activity
### path-214 (score 0.37)
- Time: 2026-09-26 19:33:01+00:00 — 2026-09-26 19:33:01+00:00
- Entities: admin_25, patch_server15
- Evidence:
  - `LAT-N-00373` | 2026-09-26 19:33:01+00:00 | network_connection | `admin_25` → `patch_server15` | score 0.33 | Privilege-related activity
### path-215 (score 0.37)
- Time: 2026-09-26 19:37:33+00:00 — 2026-09-26 19:37:33+00:00
- Entities: admin_11, patch_server17
- Evidence:
  - `LAT-N-00188` | 2026-09-26 19:37:33+00:00 | network_connection | `admin_11` → `patch_server17` | score 0.33 | Privilege-related activity
### path-216 (score 0.37)
- Time: 2026-09-26 20:03:25+00:00 — 2026-09-26 20:03:25+00:00
- Entities: admin_3, patch_server16
- Evidence:
  - `LAT-N-00394` | 2026-09-26 20:03:25+00:00 | network_connection | `admin_3` → `patch_server16` | score 0.33 | Privilege-related activity
### path-217 (score 0.37)
- Time: 2026-09-26 20:26:11+00:00 — 2026-09-26 20:26:11+00:00
- Entities: admin_17, patch_server15
- Evidence:
  - `LAT-N-00569` | 2026-09-26 20:26:11+00:00 | network_connection | `admin_17` → `patch_server15` | score 0.33 | Privilege-related activity
### path-218 (score 0.37)
- Time: 2026-09-26 21:11:58+00:00 — 2026-09-26 21:11:58+00:00
- Entities: employee_18, vpn_gateway18
- Evidence:
  - `LAT-N-00425` | 2026-09-26 21:11:58+00:00 | login_success | `employee_18` → `vpn_gateway18` | score 0.33 | Privilege-related activity
### path-219 (score 0.37)
- Time: 2026-09-26 21:18:44+00:00 — 2026-09-26 21:18:44+00:00
- Entities: admin_22, patch_server4
- Evidence:
  - `LAT-N-00634` | 2026-09-26 21:18:44+00:00 | network_connection | `admin_22` → `patch_server4` | score 0.33 | Privilege-related activity
### path-220 (score 0.37)
- Time: 2026-09-26 22:27:17+00:00 — 2026-09-26 22:27:17+00:00
- Entities: admin_10, patch_server5
- Evidence:
  - `LAT-N-00080` | 2026-09-26 22:27:17+00:00 | network_connection | `admin_10` → `patch_server5` | score 0.33 | Privilege-related activity
### path-221 (score 0.37)
- Time: 2026-09-26 23:01:06+00:00 — 2026-09-26 23:01:06+00:00
- Entities: employee_6, identity_service12
- Evidence:
  - `LAT-N-00435` | 2026-09-26 23:01:06+00:00 | login_success | `employee_6` → `identity_service12` | score 0.33 | Privilege-related activity
### path-222 (score 0.37)
- Time: 2026-09-26 23:32:19+00:00 — 2026-09-26 23:32:19+00:00
- Entities: edr_console11, endpoint_agent_10
- Evidence:
  - `LAT-N-00037` | 2026-09-26 23:32:19+00:00 | network_connection | `endpoint_agent_10` → `edr_console11` | score 0.33 | Privilege-related activity
### path-087 (score 0.34)
- Time: 2026-09-23 04:02:25+00:00 — 2026-09-23 04:02:25+00:00
- Entities: endpoint-01, identity-01
- Evidence:
  - `LAT-A-005` | 2026-09-23 04:02:25+00:00 | network_connection | `endpoint-01` → `identity-01` | score 0.3 | Unusual destination

## Candidate MITRE ATT&CK mappings
- **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)** — event `LAT-A-001` at 2026-09-23 04:00:00+00:00: Authentication-failure indicator; verify repeated attempts and source context. Evidence: Repeated failed_login from unusual account
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `LAT-A-003` at 2026-09-23 04:01:05+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Credential access and password_dump indicator
- **[T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)** — event `LAT-A-003` at 2026-09-23 04:01:05+00:00: Credential-dumping indicator; confirm with endpoint evidence. Evidence: Credential access and password_dump indicator
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `LAT-A-004` at 2026-09-23 04:01:40+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Privilege elevation and token access attempt
- **[T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/)** — event `LAT-A-006` at 2026-09-23 04:03:10+00:00: Remote-service indicator; confirm the service and remote execution context. Evidence: Remote service activity suggests lateral movement
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `LAT-A-008` at 2026-09-23 04:05:00+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Sensitive payroll archive staging
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `LAT-A-008` at 2026-09-23 04:05:00+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Sensitive payroll archive staging
- **[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)** — event `LAT-A-009` at 2026-09-23 04:05:55+00:00: PowerShell/encoded-command indicator; verify process command line and parent. Evidence: Unusual external destination following staging
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `LAT-A-009` at 2026-09-23 04:05:55+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Unusual external destination following staging

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.