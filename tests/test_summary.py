from pathlib import Path
import pandas as pd
from src.normalize import normalize_frame
from src.detect import score_events
from src.graph import build_graph, reduce_graph
from src.trace import candidate_paths
from src.attack_mapping import map_attack_techniques
from src.evaluate import evaluate
from src.summarize import build_summary, summary_markdown

ROOT = Path(__file__).resolve().parents[1]

def test_summary_is_evidence_linked():
    raw = pd.read_csv(ROOT / "data" / "company_week_logs.csv")
    df = score_events(normalize_frame(raw))
    df["is_suspicious"] = df.anomaly_score >= 0.28
    graph = build_graph(df)
    reduced, kept = reduce_graph(graph, df, 0.28)
    metrics = evaluate(df, graph, reduced, kept)
    paths = candidate_paths(df)
    techniques = map_attack_techniques(df[df.is_suspicious])
    summary = build_summary("company test", df, metrics, paths, techniques)
    report = summary_markdown(summary, techniques)
    assert summary["event_count"] == len(df)
    assert "Executive summary" in report
    if summary["top_events"]:
        event_id = summary["top_events"][0]["event_id"]
        assert event_id in report
        assert f"#evidence-{event_id}" in report
