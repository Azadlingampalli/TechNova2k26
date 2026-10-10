"""Run the synthetic benchmark across all six bundled scenarios."""
import json
import subprocess
import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent
SCENARIOS = {
    "company": "data/company_week_logs.csv",
    "college_website": "data/college_website_week_logs.csv",
    "enterprise_endpoint": "data/enterprise_endpoint_week_logs.csv",
    "ransomware_extra": "data/ransomware_incident_extra.csv",
    "web_server_intrusion_extra": "data/web_server_intrusion_extra.csv",
    "lateral_movement_extra": "data/lateral_movement_extra.csv",
}

def main():
    summaries = []
    for name, input_path in SCENARIOS.items():
        out = ROOT / "outputs" / name
        command = [sys.executable, str(ROOT / "run_pipeline.py"), "--input", str(ROOT / input_path), "--output", str(out), "--name", name]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"{name} failed:\n{result.stdout}\n{result.stderr}")
        metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
        summaries.append({"scenario": name, **metrics})
    summary_dir = ROOT / "outputs"
    summary_dir.mkdir(exist_ok=True)
    pd.DataFrame(summaries).to_csv(summary_dir / "scenario_summary.csv", index=False)
    (summary_dir / "scenario_summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    columns = ["scenario", "events", "ground_truth_attack_events", "detected_events", "precision", "recall", "f1", "node_reduction_pct", "edge_reduction_pct", "attack_event_retention_pct", "analyst_time_to_insight_seconds"]
    print(pd.DataFrame(summaries)[columns].to_string(index=False))
    print(f"\nWrote {summary_dir / 'scenario_summary.csv'}")

if __name__ == "__main__":
    main()
