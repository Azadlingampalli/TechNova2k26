# Bundled datasets

All six bundled datasets are synthetic examples created for this educational prototype. They are not DARPA TC, LANL, or captured lab-VM data.

| CSV | Ground-truth JSON | Scenario |
|---|---|---|
| `company_week_logs.csv` | `company_week_logs_ground_truth.json` | Company environment |
| `college_website_week_logs.csv` | `college_website_week_logs_ground_truth.json` | College web environment |
| `enterprise_endpoint_week_logs.csv` | `enterprise_endpoint_week_logs_ground_truth.json` | Enterprise endpoint |
| `ransomware_incident_extra.csv` | `ransomware_incident_extra_ground_truth.json` | Ransomware-like file activity |
| `web_server_intrusion_extra.csv` | `web_server_intrusion_extra_ground_truth.json` | Web server intrusion indicators |
| `lateral_movement_extra.csv` | `lateral_movement_extra_ground_truth.json` | Cross-host / lateral-movement indicators |

The CSV `label` field and ground-truth JSON files are reserved for evaluation. The anomaly scorer does not use the label. For external datasets, adapt fields carefully and preserve original IDs/timestamps; do not synthesize missing causal links.
