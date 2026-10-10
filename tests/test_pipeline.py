from pathlib import Path
import pandas as pd

from src.normalize import normalize_frame
from src.detect import score_events
from src.graph import build_graph, reduce_graph
from src.trace import candidate_paths, trace_entity
from src.attack_mapping import map_attack_techniques
from src.evaluate import evaluate


ROOT = Path(__file__).resolve().parents[1]


def pipeline_for(name):
    raw = pd.read_csv(ROOT / "data" / name)
    df = score_events(normalize_frame(raw))
    df["is_suspicious"] = df["anomaly_score"] >= 0.28
    graph = build_graph(df)
    reduced, kept = reduce_graph(graph, df, 0.28)
    return raw, df, graph, reduced, kept


def test_pipeline_smoke_and_multigraph_preserves_events():
    raw, df, graph, reduced, kept = pipeline_for("company_week_logs.csv")
    assert len(df) == len(raw)
    assert graph.number_of_edges() == len(raw)
    assert isinstance(graph, __import__("networkx").MultiDiGraph)
    assert reduced.number_of_edges() <= graph.number_of_edges()
    assert isinstance(candidate_paths(df), list)
    assert kept <= set(df.event_id.astype(str))


def test_labels_are_not_used_to_score():
    raw = pd.read_csv(ROOT / "data" / "company_week_logs.csv")
    a = score_events(normalize_frame(raw))
    raw["label"] = ~raw["label"].astype(bool)
    b = score_events(normalize_frame(raw))
    assert a["anomaly_score"].tolist() == b["anomaly_score"].tolist()


def test_attack_mapping_is_event_linked():
    _, df, *_ = pipeline_for("college_website_week_logs.csv")
    findings = map_attack_techniques(df[df.is_suspicious])
    assert findings
    assert all(f["event_id"] for f in findings)
    assert all(f["mitre_url"].startswith("https://attack.mitre.org/") for f in findings)


def test_trace_returns_original_event_ids():
    _, df, graph, *_ = pipeline_for("company_week_logs.csv")
    seed = str(df.iloc[0]["source_entity"])
    result = trace_entity(graph, seed, "forward", 3)
    assert result["entity"] == seed
    assert all("event_id" in event for event in result["events"])


def test_all_three_scenarios_have_attack_ground_truth():
    expected = {
        "company_week_logs.csv": 9,
        "college_website_week_logs.csv": 7,
        "enterprise_endpoint_week_logs.csv": 8,
    }
    for name, count in expected.items():
        _, df, graph, reduced, kept = pipeline_for(name)
        assert int(df.label.sum()) == count
        metrics = evaluate(df, graph, reduced, kept)
        assert metrics["ground_truth_attack_events"] == count
        assert 0 <= metrics["node_reduction_pct"] <= 100
        assert 0 <= metrics["edge_reduction_pct"] <= 100
        assert metrics["attack_event_retention_pct"] is not None
