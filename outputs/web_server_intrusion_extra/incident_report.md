# RansomTrace AI Incident Report — web_server_intrusion_extra

## Summary
- Events analyzed: **689**
- Events flagged: **111**
- Candidate paths: **97**
- Findings are triage suggestions and require analyst validation.

## Metrics
```json
{
  "events": 689,
  "ground_truth_attack_events": 9,
  "detected_events": 111,
  "true_positives": 9,
  "false_positives": 102,
  "false_negatives": 0,
  "precision": 0.0811,
  "recall": 1.0,
  "f1": 0.15,
  "attack_event_recall": 1.0,
  "original_nodes": 286,
  "reduced_nodes": 54,
  "node_reduction_pct": 81.12,
  "original_edges": 689,
  "reduced_edges": 111,
  "edge_reduction_pct": 83.89,
  "attack_events_retained_in_reduced_graph": 9,
  "attack_event_retention_pct": 100.0,
  "retained_attack_event_ids": [
    "WEB-A-001",
    "WEB-A-002",
    "WEB-A-003",
    "WEB-A-004",
    "WEB-A-005",
    "WEB-A-006",
    "WEB-A-007",
    "WEB-A-008",
    "WEB-A-009"
  ],
  "analyst_time_to_insight_seconds": null,
  "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
  "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
}
```

## Candidate paths
### path-046 (score 0.78)
- Time: 2026-09-23 04:02:00+00:00 — 2026-09-23 04:05:05+00:00
- Entities: archive_staging.zip, college-db-01, php_shell_process, student_records, unknown_ip_203.0.113.99, web_server
- Evidence:
  - `WEB-A-005` | 2026-09-23 04:02:00+00:00 | process_start | `web_server` → `php_shell_process` | score 0.5800000000000001 | Script/command execution; Suspicious web activity
  - `WEB-A-006` | 2026-09-23 04:02:35+00:00 | network_connection | `php_shell_process` → `college-db-01` | score 0.5800000000000001 | Unusual destination; Suspicious web activity
  - `WEB-A-007` | 2026-09-23 04:03:20+00:00 | file_read | `php_shell_process` → `student_records` | score 0.5800000000000001 | Sensitive data/staging indicator; Suspicious web activity
  - `WEB-A-008` | 2026-09-23 04:04:10+00:00 | file_write | `php_shell_process` → `archive_staging.zip` | score 0.5800000000000001 | Sensitive data/staging indicator; Suspicious web activity
  - `WEB-A-009` | 2026-09-23 04:05:05+00:00 | network_connection | `php_shell_process` → `unknown_ip_203.0.113.99` | score 0.5800000000000001 | Unusual destination; Suspicious web activity
### path-043 (score 0.7)
- Time: 2026-09-23 04:00:00+00:00 — 2026-09-23 04:00:00+00:00
- Entities: cms_login, unknown_client_203.0.113.77
- Evidence:
  - `WEB-A-001` | 2026-09-23 04:00:00+00:00 | login_failed | `unknown_client_203.0.113.77` → `cms_login` | score 0.66 | Authentication failures; Privilege-related activity; Uncommon event type
### path-045 (score 0.617)
- Time: 2026-09-23 04:00:25+00:00 — 2026-09-23 04:01:25+00:00
- Entities: attacker_session, cms_dashboard, unexpected_file.php, upload_endpoint
- Evidence:
  - `WEB-A-002` | 2026-09-23 04:00:25+00:00 | login_success | `attacker_session` → `cms_dashboard` | score 0.8300000000000001 | Authentication failures; Privilege-related activity; Unusual destination
  - `WEB-A-003` | 2026-09-23 04:00:55+00:00 | http_request | `cms_dashboard` → `upload_endpoint` | score 0.33 | Suspicious web activity
  - `WEB-A-004` | 2026-09-23 04:01:25+00:00 | file_write | `upload_endpoint` → `unexpected_file.php` | score 0.33 | Suspicious web activity
### path-012 (score 0.41)
- Time: 2026-09-20 13:22:14+00:00 — 2026-09-20 14:48:23+00:00
- Entities: admin_15, admin_2, cms_dashboard4
- Evidence:
  - `WEB-N-00242` | 2026-09-20 13:22:14+00:00 | login_success | `admin_15` → `cms_dashboard4` | score 0.33 | Privilege-related activity
  - `WEB-N-00098` | 2026-09-20 14:48:23+00:00 | login_success | `admin_2` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-041 (score 0.41)
- Time: 2026-09-22 22:16:17+00:00 — 2026-09-22 22:56:43+00:00
- Entities: admin_21, admin_22, cms_dashboard11
- Evidence:
  - `WEB-N-00014` | 2026-09-22 22:16:17+00:00 | login_success | `admin_22` → `cms_dashboard11` | score 0.33 | Privilege-related activity
  - `WEB-N-00135` | 2026-09-22 22:56:43+00:00 | login_success | `admin_21` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-049 (score 0.41)
- Time: 2026-09-23 06:42:26+00:00 — 2026-09-23 07:36:30+00:00
- Entities: admin_14, admin_5, cms_dashboard1
- Evidence:
  - `WEB-N-00318` | 2026-09-23 06:42:26+00:00 | login_success | `admin_14` → `cms_dashboard1` | score 0.33 | Privilege-related activity
  - `WEB-N-00223` | 2026-09-23 07:36:30+00:00 | login_success | `admin_5` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-054 (score 0.41)
- Time: 2026-09-23 11:31:03+00:00 — 2026-09-23 13:18:42+00:00
- Entities: admin_4, admin_5, cms_dashboard16
- Evidence:
  - `WEB-N-00335` | 2026-09-23 11:31:03+00:00 | login_success | `admin_5` → `cms_dashboard16` | score 0.33 | Privilege-related activity
  - `WEB-N-00346` | 2026-09-23 13:18:42+00:00 | login_success | `admin_4` → `cms_dashboard16` | score 0.33 | Privilege-related activity
### path-071 (score 0.41)
- Time: 2026-09-24 18:43:31+00:00 — 2026-09-24 20:54:02+00:00
- Entities: admin_16, cms_dashboard1, cms_dashboard2
- Evidence:
  - `WEB-N-00094` | 2026-09-24 18:43:31+00:00 | login_success | `admin_16` → `cms_dashboard2` | score 0.33 | Privilege-related activity
  - `WEB-N-00257` | 2026-09-24 20:54:02+00:00 | login_success | `admin_16` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-077 (score 0.41)
- Time: 2026-09-25 07:53:42+00:00 — 2026-09-25 08:27:11+00:00
- Entities: admin_20, admin_5, cms_dashboard4
- Evidence:
  - `WEB-N-00384` | 2026-09-25 07:53:42+00:00 | login_success | `admin_20` → `cms_dashboard4` | score 0.33 | Privilege-related activity
  - `WEB-N-00656` | 2026-09-25 08:27:11+00:00 | login_success | `admin_5` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-085 (score 0.41)
- Time: 2026-09-26 01:41:20+00:00 — 2026-09-26 03:50:11+00:00
- Entities: admin_12, cms_dashboard10, cms_dashboard16
- Evidence:
  - `WEB-N-00408` | 2026-09-26 01:41:20+00:00 | login_success | `admin_12` → `cms_dashboard10` | score 0.33 | Privilege-related activity
  - `WEB-N-00365` | 2026-09-26 03:50:11+00:00 | login_success | `admin_12` → `cms_dashboard16` | score 0.33 | Privilege-related activity
### path-096 (score 0.41)
- Time: 2026-09-26 19:34:25+00:00 — 2026-09-26 19:51:25+00:00
- Entities: admin_25, cms_dashboard10, cms_dashboard11
- Evidence:
  - `WEB-N-00557` | 2026-09-26 19:34:25+00:00 | login_success | `admin_25` → `cms_dashboard10` | score 0.33 | Privilege-related activity
  - `WEB-N-00651` | 2026-09-26 19:51:25+00:00 | login_success | `admin_25` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-001 (score 0.37)
- Time: 2026-09-20 00:09:36+00:00 — 2026-09-20 00:09:36+00:00
- Entities: admin_2, cms_dashboard6
- Evidence:
  - `WEB-N-00563` | 2026-09-20 00:09:36+00:00 | login_success | `admin_2` → `cms_dashboard6` | score 0.33 | Privilege-related activity
### path-002 (score 0.37)
- Time: 2026-09-20 03:03:10+00:00 — 2026-09-20 03:03:10+00:00
- Entities: admin_23, cms_dashboard7
- Evidence:
  - `WEB-N-00582` | 2026-09-20 03:03:10+00:00 | login_success | `admin_23` → `cms_dashboard7` | score 0.33 | Privilege-related activity
### path-003 (score 0.37)
- Time: 2026-09-20 04:48:59+00:00 — 2026-09-20 04:48:59+00:00
- Entities: admin_20, cms_dashboard1
- Evidence:
  - `WEB-N-00495` | 2026-09-20 04:48:59+00:00 | login_success | `admin_20` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-004 (score 0.37)
- Time: 2026-09-20 06:25:31+00:00 — 2026-09-20 06:25:31+00:00
- Entities: admin_10, cms_dashboard12
- Evidence:
  - `WEB-N-00357` | 2026-09-20 06:25:31+00:00 | login_success | `admin_10` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-005 (score 0.37)
- Time: 2026-09-20 07:32:31+00:00 — 2026-09-20 07:32:31+00:00
- Entities: admin_20, cms_dashboard10
- Evidence:
  - `WEB-N-00523` | 2026-09-20 07:32:31+00:00 | login_success | `admin_20` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-006 (score 0.37)
- Time: 2026-09-20 09:13:38+00:00 — 2026-09-20 09:13:38+00:00
- Entities: admin_5, cms_dashboard18
- Evidence:
  - `WEB-N-00597` | 2026-09-20 09:13:38+00:00 | login_success | `admin_5` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-007 (score 0.37)
- Time: 2026-09-20 10:00:28+00:00 — 2026-09-20 10:00:28+00:00
- Entities: admin_11, cms_dashboard4
- Evidence:
  - `WEB-N-00052` | 2026-09-20 10:00:28+00:00 | login_success | `admin_11` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-008 (score 0.37)
- Time: 2026-09-20 10:12:19+00:00 — 2026-09-20 10:12:19+00:00
- Entities: admin_22, cms_dashboard12
- Evidence:
  - `WEB-N-00377` | 2026-09-20 10:12:19+00:00 | login_success | `admin_22` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-009 (score 0.37)
- Time: 2026-09-20 10:42:32+00:00 — 2026-09-20 10:42:32+00:00
- Entities: admin_6, cms_dashboard4
- Evidence:
  - `WEB-N-00083` | 2026-09-20 10:42:32+00:00 | login_success | `admin_6` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-010 (score 0.37)
- Time: 2026-09-20 12:58:53+00:00 — 2026-09-20 12:58:53+00:00
- Entities: admin_12, cms_dashboard12
- Evidence:
  - `WEB-N-00206` | 2026-09-20 12:58:53+00:00 | login_success | `admin_12` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-011 (score 0.37)
- Time: 2026-09-20 13:01:35+00:00 — 2026-09-20 13:01:35+00:00
- Entities: admin_25, cms_dashboard18
- Evidence:
  - `WEB-N-00062` | 2026-09-20 13:01:35+00:00 | login_success | `admin_25` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-013 (score 0.37)
- Time: 2026-09-20 15:08:46+00:00 — 2026-09-20 15:08:46+00:00
- Entities: admin_8, cms_dashboard3
- Evidence:
  - `WEB-N-00467` | 2026-09-20 15:08:46+00:00 | login_success | `admin_8` → `cms_dashboard3` | score 0.33 | Privilege-related activity
### path-014 (score 0.37)
- Time: 2026-09-20 17:36:49+00:00 — 2026-09-20 17:36:49+00:00
- Entities: admin_24, cms_dashboard7
- Evidence:
  - `WEB-N-00027` | 2026-09-20 17:36:49+00:00 | login_success | `admin_24` → `cms_dashboard7` | score 0.33 | Privilege-related activity
### path-015 (score 0.37)
- Time: 2026-09-20 17:50:27+00:00 — 2026-09-20 17:50:27+00:00
- Entities: admin_8, cms_dashboard16
- Evidence:
  - `WEB-N-00197` | 2026-09-20 17:50:27+00:00 | login_success | `admin_8` → `cms_dashboard16` | score 0.33 | Privilege-related activity
### path-016 (score 0.37)
- Time: 2026-09-20 18:55:13+00:00 — 2026-09-20 18:55:13+00:00
- Entities: admin_14, cms_dashboard18
- Evidence:
  - `WEB-N-00392` | 2026-09-20 18:55:13+00:00 | login_success | `admin_14` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-017 (score 0.37)
- Time: 2026-09-20 20:07:56+00:00 — 2026-09-20 20:07:56+00:00
- Entities: admin_19, cms_dashboard4
- Evidence:
  - `WEB-N-00055` | 2026-09-20 20:07:56+00:00 | login_success | `admin_19` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-018 (score 0.37)
- Time: 2026-09-20 23:16:44+00:00 — 2026-09-20 23:16:44+00:00
- Entities: admin_9, cms_dashboard2
- Evidence:
  - `WEB-N-00579` | 2026-09-20 23:16:44+00:00 | login_success | `admin_9` → `cms_dashboard2` | score 0.33 | Privilege-related activity
### path-019 (score 0.37)
- Time: 2026-09-20 23:50:20+00:00 — 2026-09-20 23:50:20+00:00
- Entities: admin_25, cms_dashboard14
- Evidence:
  - `WEB-N-00114` | 2026-09-20 23:50:20+00:00 | login_success | `admin_25` → `cms_dashboard14` | score 0.33 | Privilege-related activity
### path-020 (score 0.37)
- Time: 2026-09-21 00:06:38+00:00 — 2026-09-21 00:06:38+00:00
- Entities: admin_9, cms_dashboard11
- Evidence:
  - `WEB-N-00654` | 2026-09-21 00:06:38+00:00 | login_success | `admin_9` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-021 (score 0.37)
- Time: 2026-09-21 00:54:48+00:00 — 2026-09-21 00:54:48+00:00
- Entities: admin_24, cms_dashboard18
- Evidence:
  - `WEB-N-00626` | 2026-09-21 00:54:48+00:00 | login_success | `admin_24` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-022 (score 0.37)
- Time: 2026-09-21 01:29:27+00:00 — 2026-09-21 01:29:27+00:00
- Entities: admin_10, cms_dashboard1
- Evidence:
  - `WEB-N-00532` | 2026-09-21 01:29:27+00:00 | login_success | `admin_10` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-023 (score 0.37)
- Time: 2026-09-21 01:44:23+00:00 — 2026-09-21 01:44:23+00:00
- Entities: admin_12, cms_dashboard16
- Evidence:
  - `WEB-N-00332` | 2026-09-21 01:44:23+00:00 | login_success | `admin_12` → `cms_dashboard16` | score 0.33 | Privilege-related activity
### path-024 (score 0.37)
- Time: 2026-09-21 02:24:58+00:00 — 2026-09-21 02:24:58+00:00
- Entities: admin_6, cms_dashboard5
- Evidence:
  - `WEB-N-00148` | 2026-09-21 02:24:58+00:00 | login_success | `admin_6` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-025 (score 0.37)
- Time: 2026-09-21 04:30:50+00:00 — 2026-09-21 04:30:50+00:00
- Entities: admin_15, cms_dashboard15
- Evidence:
  - `WEB-N-00448` | 2026-09-21 04:30:50+00:00 | login_success | `admin_15` → `cms_dashboard15` | score 0.33 | Privilege-related activity
### path-026 (score 0.37)
- Time: 2026-09-21 11:22:54+00:00 — 2026-09-21 11:22:54+00:00
- Entities: admin_22, cms_dashboard7
- Evidence:
  - `WEB-N-00336` | 2026-09-21 11:22:54+00:00 | login_success | `admin_22` → `cms_dashboard7` | score 0.33 | Privilege-related activity
### path-027 (score 0.37)
- Time: 2026-09-21 13:08:44+00:00 — 2026-09-21 13:08:44+00:00
- Entities: admin_24, cms_dashboard6
- Evidence:
  - `WEB-N-00256` | 2026-09-21 13:08:44+00:00 | login_success | `admin_24` → `cms_dashboard6` | score 0.33 | Privilege-related activity
### path-028 (score 0.37)
- Time: 2026-09-21 16:51:00+00:00 — 2026-09-21 16:51:00+00:00
- Entities: admin_19, cms_dashboard18
- Evidence:
  - `WEB-N-00544` | 2026-09-21 16:51:00+00:00 | login_success | `admin_19` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-029 (score 0.37)
- Time: 2026-09-21 18:51:12+00:00 — 2026-09-21 18:51:12+00:00
- Entities: admin_1, cms_dashboard17
- Evidence:
  - `WEB-N-00079` | 2026-09-21 18:51:12+00:00 | login_success | `admin_1` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-030 (score 0.37)
- Time: 2026-09-21 20:23:14+00:00 — 2026-09-21 20:23:14+00:00
- Entities: admin_22, cms_dashboard6
- Evidence:
  - `WEB-N-00555` | 2026-09-21 20:23:14+00:00 | login_success | `admin_22` → `cms_dashboard6` | score 0.33 | Privilege-related activity
### path-031 (score 0.37)
- Time: 2026-09-21 23:25:31+00:00 — 2026-09-21 23:25:31+00:00
- Entities: admin_17, cms_dashboard12
- Evidence:
  - `WEB-N-00239` | 2026-09-21 23:25:31+00:00 | login_success | `admin_17` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-032 (score 0.37)
- Time: 2026-09-21 23:38:36+00:00 — 2026-09-21 23:38:36+00:00
- Entities: admin_24, cms_dashboard9
- Evidence:
  - `WEB-N-00405` | 2026-09-21 23:38:36+00:00 | login_success | `admin_24` → `cms_dashboard9` | score 0.33 | Privilege-related activity
### path-033 (score 0.37)
- Time: 2026-09-22 01:09:29+00:00 — 2026-09-22 01:09:29+00:00
- Entities: admin_15, cms_dashboard17
- Evidence:
  - `WEB-N-00116` | 2026-09-22 01:09:29+00:00 | login_success | `admin_15` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-034 (score 0.37)
- Time: 2026-09-22 02:40:08+00:00 — 2026-09-22 02:40:08+00:00
- Entities: admin_21, cms_dashboard11
- Evidence:
  - `WEB-N-00029` | 2026-09-22 02:40:08+00:00 | login_success | `admin_21` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-035 (score 0.37)
- Time: 2026-09-22 06:49:44+00:00 — 2026-09-22 06:49:44+00:00
- Entities: admin_24, cms_dashboard5
- Evidence:
  - `WEB-N-00638` | 2026-09-22 06:49:44+00:00 | login_success | `admin_24` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-036 (score 0.37)
- Time: 2026-09-22 08:09:59+00:00 — 2026-09-22 08:09:59+00:00
- Entities: admin_4, cms_dashboard10
- Evidence:
  - `WEB-N-00343` | 2026-09-22 08:09:59+00:00 | login_success | `admin_4` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-037 (score 0.37)
- Time: 2026-09-22 10:35:40+00:00 — 2026-09-22 10:35:40+00:00
- Entities: admin_25, cms_dashboard8
- Evidence:
  - `WEB-N-00329` | 2026-09-22 10:35:40+00:00 | login_success | `admin_25` → `cms_dashboard8` | score 0.33 | Privilege-related activity
### path-038 (score 0.37)
- Time: 2026-09-22 13:55:34+00:00 — 2026-09-22 13:55:34+00:00
- Entities: admin_20, cms_dashboard11
- Evidence:
  - `WEB-N-00064` | 2026-09-22 13:55:34+00:00 | login_success | `admin_20` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-039 (score 0.37)
- Time: 2026-09-22 17:37:12+00:00 — 2026-09-22 17:37:12+00:00
- Entities: admin_8, cms_dashboard10
- Evidence:
  - `WEB-N-00492` | 2026-09-22 17:37:12+00:00 | login_success | `admin_8` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-040 (score 0.37)
- Time: 2026-09-22 22:07:17+00:00 — 2026-09-22 22:07:17+00:00
- Entities: admin_15, cms_dashboard14
- Evidence:
  - `WEB-N-00208` | 2026-09-22 22:07:17+00:00 | login_success | `admin_15` → `cms_dashboard14` | score 0.33 | Privilege-related activity
### path-042 (score 0.37)
- Time: 2026-09-23 03:28:40+00:00 — 2026-09-23 03:28:40+00:00
- Entities: admin_7, cms_dashboard17
- Evidence:
  - `WEB-N-00650` | 2026-09-23 03:28:40+00:00 | login_success | `admin_7` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-044 (score 0.37)
- Time: 2026-09-23 04:00:00+00:00 — 2026-09-23 04:00:00+00:00
- Entities: admin_4, cms_dashboard17
- Evidence:
  - `WEB-N-00315` | 2026-09-23 04:00:00+00:00 | login_success | `admin_4` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-047 (score 0.37)
- Time: 2026-09-23 04:37:51+00:00 — 2026-09-23 04:37:51+00:00
- Entities: admin_1, cms_dashboard8
- Evidence:
  - `WEB-N-00314` | 2026-09-23 04:37:51+00:00 | login_success | `admin_1` → `cms_dashboard8` | score 0.33 | Privilege-related activity
### path-048 (score 0.37)
- Time: 2026-09-23 05:19:24+00:00 — 2026-09-23 05:19:24+00:00
- Entities: admin_5, cms_dashboard10
- Evidence:
  - `WEB-N-00515` | 2026-09-23 05:19:24+00:00 | login_success | `admin_5` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-050 (score 0.37)
- Time: 2026-09-23 09:16:52+00:00 — 2026-09-23 09:16:52+00:00
- Entities: admin_2, cms_dashboard8
- Evidence:
  - `WEB-N-00574` | 2026-09-23 09:16:52+00:00 | login_success | `admin_2` → `cms_dashboard8` | score 0.33 | Privilege-related activity
### path-051 (score 0.37)
- Time: 2026-09-23 09:48:23+00:00 — 2026-09-23 09:48:23+00:00
- Entities: admin_21, cms_dashboard1
- Evidence:
  - `WEB-N-00101` | 2026-09-23 09:48:23+00:00 | login_success | `admin_21` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-052 (score 0.37)
- Time: 2026-09-23 09:57:54+00:00 — 2026-09-23 09:57:54+00:00
- Entities: admin_1, cms_dashboard15
- Evidence:
  - `WEB-N-00451` | 2026-09-23 09:57:54+00:00 | login_success | `admin_1` → `cms_dashboard15` | score 0.33 | Privilege-related activity
### path-053 (score 0.37)
- Time: 2026-09-23 10:01:08+00:00 — 2026-09-23 10:01:08+00:00
- Entities: admin_23, cms_dashboard13
- Evidence:
  - `WEB-N-00004` | 2026-09-23 10:01:08+00:00 | login_success | `admin_23` → `cms_dashboard13` | score 0.33 | Privilege-related activity
### path-055 (score 0.37)
- Time: 2026-09-23 13:55:16+00:00 — 2026-09-23 13:55:16+00:00
- Entities: admin_15, cms_dashboard4
- Evidence:
  - `WEB-N-00120` | 2026-09-23 13:55:16+00:00 | login_success | `admin_15` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-056 (score 0.37)
- Time: 2026-09-23 16:13:09+00:00 — 2026-09-23 16:13:09+00:00
- Entities: admin_12, cms_dashboard13
- Evidence:
  - `WEB-N-00227` | 2026-09-23 16:13:09+00:00 | login_success | `admin_12` → `cms_dashboard13` | score 0.33 | Privilege-related activity
### path-057 (score 0.37)
- Time: 2026-09-23 17:52:14+00:00 — 2026-09-23 17:52:14+00:00
- Entities: admin_3, cms_dashboard15
- Evidence:
  - `WEB-N-00122` | 2026-09-23 17:52:14+00:00 | login_success | `admin_3` → `cms_dashboard15` | score 0.33 | Privilege-related activity
### path-058 (score 0.37)
- Time: 2026-09-23 21:20:13+00:00 — 2026-09-23 21:20:13+00:00
- Entities: admin_19, cms_dashboard6
- Evidence:
  - `WEB-N-00049` | 2026-09-23 21:20:13+00:00 | login_success | `admin_19` → `cms_dashboard6` | score 0.33 | Privilege-related activity
### path-059 (score 0.37)
- Time: 2026-09-23 21:24:28+00:00 — 2026-09-23 21:24:28+00:00
- Entities: admin_13, cms_dashboard1
- Evidence:
  - `WEB-N-00051` | 2026-09-23 21:24:28+00:00 | login_success | `admin_13` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-060 (score 0.37)
- Time: 2026-09-23 21:50:05+00:00 — 2026-09-23 21:50:05+00:00
- Entities: admin_2, cms_dashboard5
- Evidence:
  - `WEB-N-00037` | 2026-09-23 21:50:05+00:00 | login_success | `admin_2` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-061 (score 0.37)
- Time: 2026-09-23 22:30:37+00:00 — 2026-09-23 22:30:37+00:00
- Entities: admin_15, cms_dashboard12
- Evidence:
  - `WEB-N-00464` | 2026-09-23 22:30:37+00:00 | login_success | `admin_15` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-062 (score 0.37)
- Time: 2026-09-23 22:36:32+00:00 — 2026-09-23 22:36:32+00:00
- Entities: admin_6, cms_dashboard1
- Evidence:
  - `WEB-N-00355` | 2026-09-23 22:36:32+00:00 | login_success | `admin_6` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-063 (score 0.37)
- Time: 2026-09-23 23:19:12+00:00 — 2026-09-23 23:19:12+00:00
- Entities: admin_5, cms_dashboard13
- Evidence:
  - `WEB-N-00338` | 2026-09-23 23:19:12+00:00 | login_success | `admin_5` → `cms_dashboard13` | score 0.33 | Privilege-related activity
### path-064 (score 0.37)
- Time: 2026-09-24 00:52:47+00:00 — 2026-09-24 00:52:47+00:00
- Entities: admin_15, cms_dashboard10
- Evidence:
  - `WEB-N-00428` | 2026-09-24 00:52:47+00:00 | login_success | `admin_15` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-065 (score 0.37)
- Time: 2026-09-24 01:15:43+00:00 — 2026-09-24 01:15:43+00:00
- Entities: admin_7, cms_dashboard18
- Evidence:
  - `WEB-N-00013` | 2026-09-24 01:15:43+00:00 | login_success | `admin_7` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-066 (score 0.37)
- Time: 2026-09-24 03:41:09+00:00 — 2026-09-24 03:41:09+00:00
- Entities: admin_3, cms_dashboard5
- Evidence:
  - `WEB-N-00394` | 2026-09-24 03:41:09+00:00 | login_success | `admin_3` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-067 (score 0.37)
- Time: 2026-09-24 08:39:00+00:00 — 2026-09-24 08:39:00+00:00
- Entities: admin_16, cms_dashboard14
- Evidence:
  - `WEB-N-00663` | 2026-09-24 08:39:00+00:00 | login_success | `admin_16` → `cms_dashboard14` | score 0.33 | Privilege-related activity
### path-068 (score 0.37)
- Time: 2026-09-24 15:10:35+00:00 — 2026-09-24 15:10:35+00:00
- Entities: admin_25, cms_dashboard3
- Evidence:
  - `WEB-N-00080` | 2026-09-24 15:10:35+00:00 | login_success | `admin_25` → `cms_dashboard3` | score 0.33 | Privilege-related activity
### path-069 (score 0.37)
- Time: 2026-09-24 18:04:04+00:00 — 2026-09-24 18:04:04+00:00
- Entities: admin_23, cms_dashboard5
- Evidence:
  - `WEB-N-00005` | 2026-09-24 18:04:04+00:00 | login_success | `admin_23` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-070 (score 0.37)
- Time: 2026-09-24 18:35:58+00:00 — 2026-09-24 18:35:58+00:00
- Entities: admin_2, cms_dashboard3
- Evidence:
  - `WEB-N-00031` | 2026-09-24 18:35:58+00:00 | login_success | `admin_2` → `cms_dashboard3` | score 0.33 | Privilege-related activity
### path-072 (score 0.37)
- Time: 2026-09-24 23:09:12+00:00 — 2026-09-24 23:09:12+00:00
- Entities: admin_24, cms_dashboard4
- Evidence:
  - `WEB-N-00153` | 2026-09-24 23:09:12+00:00 | login_success | `admin_24` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-073 (score 0.37)
- Time: 2026-09-25 01:26:07+00:00 — 2026-09-25 01:26:07+00:00
- Entities: admin_10, cms_dashboard5
- Evidence:
  - `WEB-N-00349` | 2026-09-25 01:26:07+00:00 | login_success | `admin_10` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-074 (score 0.37)
- Time: 2026-09-25 01:40:21+00:00 — 2026-09-25 01:40:21+00:00
- Entities: admin_25, cms_dashboard17
- Evidence:
  - `WEB-N-00182` | 2026-09-25 01:40:21+00:00 | login_success | `admin_25` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-075 (score 0.37)
- Time: 2026-09-25 02:30:40+00:00 — 2026-09-25 02:30:40+00:00
- Entities: admin_9, cms_dashboard18
- Evidence:
  - `WEB-N-00305` | 2026-09-25 02:30:40+00:00 | login_success | `admin_9` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-076 (score 0.37)
- Time: 2026-09-25 07:40:29+00:00 — 2026-09-25 07:40:29+00:00
- Entities: admin_22, cms_dashboard11
- Evidence:
  - `WEB-N-00657` | 2026-09-25 07:40:29+00:00 | login_success | `admin_22` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-078 (score 0.37)
- Time: 2026-09-25 09:07:34+00:00 — 2026-09-25 09:07:34+00:00
- Entities: admin_21, cms_dashboard2
- Evidence:
  - `WEB-N-00207` | 2026-09-25 09:07:34+00:00 | login_success | `admin_21` → `cms_dashboard2` | score 0.33 | Privilege-related activity
### path-079 (score 0.37)
- Time: 2026-09-25 16:18:11+00:00 — 2026-09-25 16:18:11+00:00
- Entities: admin_23, cms_dashboard9
- Evidence:
  - `WEB-N-00419` | 2026-09-25 16:18:11+00:00 | login_success | `admin_23` → `cms_dashboard9` | score 0.33 | Privilege-related activity
### path-080 (score 0.37)
- Time: 2026-09-25 18:13:53+00:00 — 2026-09-25 18:13:53+00:00
- Entities: admin_3, cms_dashboard18
- Evidence:
  - `WEB-N-00358` | 2026-09-25 18:13:53+00:00 | login_success | `admin_3` → `cms_dashboard18` | score 0.33 | Privilege-related activity
### path-081 (score 0.37)
- Time: 2026-09-25 20:37:52+00:00 — 2026-09-25 20:37:52+00:00
- Entities: admin_8, cms_dashboard11
- Evidence:
  - `WEB-N-00127` | 2026-09-25 20:37:52+00:00 | login_success | `admin_8` → `cms_dashboard11` | score 0.33 | Privilege-related activity
### path-082 (score 0.37)
- Time: 2026-09-25 23:55:54+00:00 — 2026-09-25 23:55:54+00:00
- Entities: admin_4, cms_dashboard1
- Evidence:
  - `WEB-N-00506` | 2026-09-25 23:55:54+00:00 | login_success | `admin_4` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-083 (score 0.37)
- Time: 2026-09-26 00:32:45+00:00 — 2026-09-26 00:32:45+00:00
- Entities: admin_5, cms_dashboard7
- Evidence:
  - `WEB-N-00472` | 2026-09-26 00:32:45+00:00 | login_success | `admin_5` → `cms_dashboard7` | score 0.33 | Privilege-related activity
### path-084 (score 0.37)
- Time: 2026-09-26 00:53:44+00:00 — 2026-09-26 00:53:44+00:00
- Entities: admin_21, cms_dashboard17
- Evidence:
  - `WEB-N-00149` | 2026-09-26 00:53:44+00:00 | login_success | `admin_21` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-086 (score 0.37)
- Time: 2026-09-26 04:24:28+00:00 — 2026-09-26 04:24:28+00:00
- Entities: admin_11, cms_dashboard4
- Evidence:
  - `WEB-N-00319` | 2026-09-26 04:24:28+00:00 | login_success | `admin_11` → `cms_dashboard4` | score 0.33 | Privilege-related activity
### path-087 (score 0.37)
- Time: 2026-09-26 08:16:31+00:00 — 2026-09-26 08:16:31+00:00
- Entities: admin_25, cms_dashboard9
- Evidence:
  - `WEB-N-00024` | 2026-09-26 08:16:31+00:00 | login_success | `admin_25` → `cms_dashboard9` | score 0.33 | Privilege-related activity
### path-088 (score 0.37)
- Time: 2026-09-26 09:15:52+00:00 — 2026-09-26 09:15:52+00:00
- Entities: admin_11, cms_dashboard6
- Evidence:
  - `WEB-N-00443` | 2026-09-26 09:15:52+00:00 | login_success | `admin_11` → `cms_dashboard6` | score 0.33 | Privilege-related activity
### path-089 (score 0.37)
- Time: 2026-09-26 10:31:27+00:00 — 2026-09-26 10:31:27+00:00
- Entities: admin_3, cms_dashboard5
- Evidence:
  - `WEB-N-00177` | 2026-09-26 10:31:27+00:00 | login_success | `admin_3` → `cms_dashboard5` | score 0.33 | Privilege-related activity
### path-090 (score 0.37)
- Time: 2026-09-26 10:43:41+00:00 — 2026-09-26 10:43:41+00:00
- Entities: admin_16, cms_dashboard10
- Evidence:
  - `WEB-N-00383` | 2026-09-26 10:43:41+00:00 | login_success | `admin_16` → `cms_dashboard10` | score 0.33 | Privilege-related activity
### path-091 (score 0.37)
- Time: 2026-09-26 11:11:20+00:00 — 2026-09-26 11:11:20+00:00
- Entities: admin_22, cms_dashboard7
- Evidence:
  - `WEB-N-00093` | 2026-09-26 11:11:20+00:00 | login_success | `admin_22` → `cms_dashboard7` | score 0.33 | Privilege-related activity
### path-092 (score 0.37)
- Time: 2026-09-26 11:35:34+00:00 — 2026-09-26 11:35:34+00:00
- Entities: admin_7, cms_dashboard1
- Evidence:
  - `WEB-N-00366` | 2026-09-26 11:35:34+00:00 | login_success | `admin_7` → `cms_dashboard1` | score 0.33 | Privilege-related activity
### path-093 (score 0.37)
- Time: 2026-09-26 12:51:47+00:00 — 2026-09-26 12:51:47+00:00
- Entities: admin_1, cms_dashboard14
- Evidence:
  - `WEB-N-00634` | 2026-09-26 12:51:47+00:00 | login_success | `admin_1` → `cms_dashboard14` | score 0.33 | Privilege-related activity
### path-094 (score 0.37)
- Time: 2026-09-26 13:24:54+00:00 — 2026-09-26 13:24:54+00:00
- Entities: admin_8, cms_dashboard12
- Evidence:
  - `WEB-N-00524` | 2026-09-26 13:24:54+00:00 | login_success | `admin_8` → `cms_dashboard12` | score 0.33 | Privilege-related activity
### path-095 (score 0.37)
- Time: 2026-09-26 18:50:16+00:00 — 2026-09-26 18:50:16+00:00
- Entities: admin_17, cms_dashboard17
- Evidence:
  - `WEB-N-00258` | 2026-09-26 18:50:16+00:00 | login_success | `admin_17` → `cms_dashboard17` | score 0.33 | Privilege-related activity
### path-097 (score 0.37)
- Time: 2026-09-26 23:08:15+00:00 — 2026-09-26 23:08:15+00:00
- Entities: admin_3, cms_dashboard17
- Evidence:
  - `WEB-N-00496` | 2026-09-26 23:08:15+00:00 | login_success | `admin_3` → `cms_dashboard17` | score 0.33 | Privilege-related activity

## Candidate MITRE ATT&CK mappings
- **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)** — event `WEB-A-001` at 2026-09-23 04:00:00+00:00: Authentication-failure indicator; verify repeated attempts and source context. Evidence: Repeated failed login attempts to CMS admin
- **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)** — event `WEB-A-002` at 2026-09-23 04:00:25+00:00: Authentication-failure indicator; verify repeated attempts and source context. Evidence: Unusual admin login after auth_failure burst
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `WEB-A-004` at 2026-09-23 04:01:25+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: webshell unexpected_file.php uploaded to web root
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `WEB-A-005` at 2026-09-23 04:02:00+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: php webshell launched shell script
- **[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)** — event `WEB-A-006` at 2026-09-23 04:02:35+00:00: Possible web-shell indicator; verify uploaded file and execution evidence. Evidence: Unusual server-to-database connection after webshell
- **[T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)** — event `WEB-A-008` at 2026-09-23 04:04:10+00:00: Archive/staging indicator; confirm that data was collected for transfer. Evidence: Sensitive data staging and archive compression
- **[T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)** — event `WEB-A-009` at 2026-09-23 04:05:05+00:00: Possible transfer indicator; a network connection alone is insufficient evidence. Evidence: External destination with possible data exfiltration

## Limitations
- Rule-based detector; false positives and false negatives are expected.
- Candidate paths are entity-linked chronological groupings, not causal proof.
- ATT&CK mappings are hypotheses.
- Reduction is not guaranteed to preserve every attack path.
- Time-to-insight must be measured in a controlled analyst study.