from pathlib import Path
import hashlib
import json
import os
import tempfile

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.normalize import normalize_frame
from src.detect import score_events
from src.graph import build_graph, reduce_graph
from src.trace import candidate_paths, trace_entity
from src.attack_mapping import map_attack_techniques
from src.evaluate import evaluate
from src.report import generate_report
from src.summarize import build_summary, summary_markdown
from src.storage import connection_status, save_analysis, list_runs, search_events

ROOT = Path(__file__).parent
st.set_page_config(page_title="RansomTrace AI | Incident Workbench", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1600px;}
[data-testid="stMetric"] {background: rgba(120,120,120,.07); padding: 14px 16px; border-radius: 12px; border: 1px solid rgba(120,120,120,.18);}
.rt-subtitle {color: #687385; margin-top: -0.6rem; margin-bottom: 1.2rem;}
.rt-section {padding: 0.75rem 0 0.25rem 0;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ RansomTrace AI")
st.markdown('<div class="rt-subtitle">Incident reconstruction workbench · provenance graphs · evidence-linked findings · investigation history</div>', unsafe_allow_html=True)


def graph_figure(graph, title, max_nodes=250):
    if graph.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(title=title, annotations=[dict(text="No graph data", showarrow=False)])
        return fig, 0
    view = graph
    if graph.number_of_nodes() > max_nodes:
        ranked = sorted(graph.degree, key=lambda item: item[1], reverse=True)[:max_nodes]
        view = graph.subgraph({node for node, _ in ranked}).copy()
    truncated = graph.number_of_nodes() - view.number_of_nodes()
    pos = nx.spring_layout(view, seed=17, iterations=45)
    edge_x, edge_y = [], []
    for u, v, *_ in view.edges(keys=True):
        x0, y0 = pos[u]; x1, y1 = pos[v]
        edge_x += [x0, x1, None]; edge_y += [y0, y1, None]
    edge_trace = go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(width=.7), hoverinfo="skip", name="Relationships")
    node_x, node_y, hover, labels = [], [], [], []
    suspicious_nodes = set()
    for u, v, data in view.edges(data=True):
        if data.get("suspicious"):
            suspicious_nodes.update([u, v])
    for node in view.nodes:
        x, y = pos[node]; node_x.append(x); node_y.append(y); labels.append(str(node)[:24])
        hover.append(f"Entity: {node}<br>Degree: {view.degree(node)}" + ("<br>Touches a flagged event" if node in suspicious_nodes else ""))
    node_trace = go.Scatter(x=node_x, y=node_y, mode="markers+text", text=labels, textposition="top center", hovertext=hover, hoverinfo="text", marker=dict(size=10, line=dict(width=1)), name="Entities")
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(title=title, showlegend=False, height=620, margin=dict(l=10,r=10,t=50,b=10), xaxis=dict(visible=False), yaxis=dict(visible=False), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
    return fig, truncated


def event_evidence_table(frame):
    if frame.empty:
        st.info("No matching events.")
        return
    cols = [c for c in ["event_id", "timestamp", "anomaly_score", "is_suspicious", "event_type", "host", "source_entity", "target_entity", "reasons", "details"] if c in frame.columns]
    st.dataframe(frame[cols], use_container_width=True, hide_index=True)

with st.sidebar:
    st.markdown("### Investigation setup")
    scenario = st.selectbox("Dataset / scenario", [
        "Company weekly sample", "College website weekly sample", "Enterprise endpoint sample",
        "Ransomware incident (extra)", "Web server intrusion (extra)", "Lateral movement (extra)", "Upload CSV"
    ])
    threshold = st.slider("Suspicious score threshold", 0.10, 0.90, 0.28, 0.01)
    st.caption("Heuristic scores prioritize review; they do not confirm compromise.")
    st.divider()
    db_status = connection_status()
    if db_status["connected"]:
        st.success(f"MongoDB connected · {db_status['runs']} saved investigations")
    else:
        st.warning("MongoDB unavailable · current analysis still works")
        st.caption("Start local MongoDB and restart/refresh this page to enable persistent history.")
    st.caption("Analyze only logs you are authorized to access.")

filemap = {
    "Company weekly sample": "company_week_logs.csv",
    "College website weekly sample": "college_website_week_logs.csv",
    "Enterprise endpoint sample": "enterprise_endpoint_week_logs.csv",
    "Ransomware incident (extra)": "ransomware_incident_extra.csv",
    "Web server intrusion (extra)": "web_server_intrusion_extra.csv",
    "Lateral movement (extra)": "lateral_movement_extra.csv",
}
upload = st.file_uploader("Upload security log CSV", type=["csv"]) if scenario == "Upload CSV" else None
if scenario == "Upload CSV" and upload is None:
    st.info("Upload a CSV to begin. The loader normalizes common timestamp, source, target, event type, host, and details columns.")
    st.stop()

try:
    raw = pd.read_csv(upload) if upload is not None else pd.read_csv(ROOT / "data" / filemap[scenario])
    normalized = normalize_frame(raw)
    df = score_events(normalized)
    df["is_suspicious"] = df["anomaly_score"] >= threshold
    graph = build_graph(df)
    reduced_graph, kept_ids = reduce_graph(graph, df, threshold)
    paths = candidate_paths(df)
    techniques = map_attack_techniques(df[df["is_suspicious"]])
except Exception as exc:
    st.error(f"Could not process the input: {exc}")
    st.stop()

input_name = upload.name if upload is not None else scenario
metrics = evaluate(df, graph, reduced_graph, kept_event_ids=kept_ids)
summary = build_summary(input_name, df, metrics, paths, techniques)
report_md = summary_markdown(summary, techniques)
raw_hash = hashlib.sha256(pd.util.hash_pandas_object(raw.astype(str), index=True).values.tobytes()).hexdigest()
signature = hashlib.sha256(f"{input_name}|{raw_hash}|{threshold}".encode()).hexdigest()

run_doc = {
    "scenario": input_name, "threshold": float(threshold), "metrics": metrics,
    "summary": summary, "source_filename": input_name,
    "event_count": int(len(df)), "flagged_count": int(df.is_suspicious.sum()),
    "node_count": int(graph.number_of_nodes()), "edge_count": int(graph.number_of_edges()),
}
if "saved_signature" not in st.session_state:
    st.session_state.saved_signature = None
if db_status["connected"] and st.session_state.saved_signature != signature:
    rows = df.copy()
    rows["timestamp"] = rows["timestamp"].astype(str)
    event_docs = rows.to_dict(orient="records")
    saved_id, created, save_error = save_analysis(signature, run_doc, event_docs)
    if saved_id:
        st.session_state.saved_signature = signature
        st.session_state.current_run_id = saved_id
        if created:
            st.toast("Investigation saved to MongoDB history", icon="💾")
    elif save_error:
        st.warning(f"Could not save investigation history: {save_error}")

st.caption(f"**Input:** {input_name} · **Time range:** {summary['time_start']} → {summary['time_end']} · **Scenario ID:** `{getattr(st.session_state, 'current_run_id', 'not persisted')}`")
if not db_status["connected"]:
    st.info("MongoDB is not connected. Analysis is available for this session, but it will not be retained in persistent history until MongoDB is running.")

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Events reviewed", f"{len(df):,}")
m2.metric("Flagged for review", f"{int(df.is_suspicious.sum()):,}")
m3.metric("Triage priority", summary["severity"])
m4.metric("Node reduction", f"{metrics['node_reduction_pct']}%")
m5.metric("Known attack recall", "N/A" if metrics["attack_event_recall"] is None else f"{metrics['attack_event_recall']*100:.1f}%")
st.warning("Analyst note: findings, paths, and ATT&CK mappings are hypotheses. Confirm them against source logs before declaring an incident.")

tabs = st.tabs(["Executive summary", "Timeline & overview", "Log search & evidence", "Provenance graph", "Backward / forward trace", "MITRE ATT&CK", "History & saved results", "Metrics & exports"])

with tabs[0]:
    st.subheader("Natural-language incident summary")
    st.write(summary["overview"])
    c1, c2, c3 = st.columns(3)
    c1.metric("Candidate paths", summary["candidate_path_count"])
    c2.metric("ATT&CK candidates", summary["technique_count"])
    c3.metric("Hosts with flagged activity", len(summary["hosts"]))
    if summary["hosts"]:
        st.markdown("**Hosts to review:** " + " · ".join(f"`{h}`" for h in summary["hosts"]))
    st.markdown("#### Highest-priority evidence")
    if summary["top_events"]:
        for e in summary["top_events"][:8]:
            with st.expander(f"{e['event_id']} · {e['event_type']} · score {e['score']:.2f} · {e['host'] or 'unknown host'}"):
                st.write(f"**Why flagged:** {e['reasons']}")
                st.write(f"**Relationship:** `{e['source']}` → `{e['target']}`")
                st.write(f"**Timestamp:** {e['timestamp']}")
                st.write(f"**Details:** {e['details'] or 'No detail field supplied'}")
                st.caption(f"Evidence reference: event_id = {e['event_id']}. Search this ID in the Log search & evidence tab.")
    else:
        st.success("No events crossed the configured threshold. This does not prove that the environment is benign.")
    st.markdown("#### Recommended analyst actions")
    for i, recommendation in enumerate(summary["recommendations"], 1):
        st.markdown(f"{i}. {recommendation}")
    st.markdown("#### Caveats")
    for caveat in summary["caveats"]:
        st.caption("• " + caveat)
    st.download_button("Download evidence-linked incident report (.md)", report_md.encode("utf-8"), f"{input_name.replace(' ', '_').lower()}_incident_report.md", "text/markdown", key="summary_report")

with tabs[1]:
    st.subheader("Activity timeline")
    plot = df.copy(); plot["hour"] = plot.timestamp.dt.floor("h")
    agg = plot.groupby(["hour", "is_suspicious"]).size().reset_index(name="events")
    if not agg.empty:
        st.plotly_chart(px.line(agg, x="hour", y="events", color="is_suspicious", markers=True, labels={"hour":"Time (UTC)","events":"Events","is_suspicious":"Flagged"}), use_container_width=True)
    a, b = st.columns(2)
    with a:
        st.markdown("#### Event types")
        counts = df.event_type.value_counts().head(15).rename_axis("event_type").reset_index(name="count")
        st.plotly_chart(px.bar(counts, x="count", y="event_type", orientation="h"), use_container_width=True)
    with b:
        st.markdown("#### Highest-scoring events")
        event_evidence_table(df.sort_values("anomaly_score", ascending=False).head(20))
    with st.expander("Preview original log records"):
        st.dataframe(raw.head(100), use_container_width=True, hide_index=True)

with tabs[2]:
    st.subheader("Search event evidence")
    st.caption("Search the current dataset by event ID, host, process/entity, event type, details, or detection rationale.")
    q1, q2 = st.columns([3, 1])
    with q1:
        query = st.text_input("Search current logs", placeholder="e.g. EVT-00012, powershell, web01, external")
    with q2:
        filter_flagged = st.checkbox("Flagged only", value=False)
    searchable = df.copy()
    if query.strip():
        mask = pd.Series(False, index=searchable.index)
        for col in ["event_id", "source_entity", "target_entity", "host", "event_type", "details", "reasons", "process_id"]:
            if col in searchable:
                mask |= searchable[col].astype(str).str.contains(query.strip(), case=False, regex=False, na=False)
        searchable = searchable[mask]
    if filter_flagged:
        searchable = searchable[searchable.is_suspicious]
    st.write(f"**{len(searchable):,}** matching event(s)")
    event_evidence_table(searchable.head(1000))
    st.download_button("Export matching evidence CSV", searchable.to_csv(index=False).encode("utf-8"), "matching_log_evidence.csv", "text/csv", key="export_search")
    st.markdown("#### Inspect one event")
    event_ids = df.event_id.astype(str).tolist()
    selected_event = st.selectbox("Choose event ID", event_ids, index=0 if event_ids else None)
    if selected_event:
        row = df[df.event_id.astype(str) == selected_event].iloc[0]
        st.json({k: (v.isoformat() if hasattr(v, "isoformat") else (v.item() if hasattr(v, "item") else v)) for k, v in row.to_dict().items()})

with tabs[3]:
    which_graph = st.radio("Graph view", ["Original graph", "Reduced graph"], horizontal=True)
    selected_graph = graph if which_graph == "Original graph" else reduced_graph
    fig, truncated = graph_figure(selected_graph, which_graph)
    st.plotly_chart(fig, use_container_width=True)
    if truncated:
        st.caption(f"For display performance only, {truncated} nodes are hidden from this visualization. Evaluation uses the full graph.")
    st.caption(f"Nodes: {selected_graph.number_of_nodes():,} · Relationships: {selected_graph.number_of_edges():,}")
    edge_rows = [{"source":u,"target":v,**data} for u,v,k,data in selected_graph.edges(keys=True, data=True)]
    if edge_rows:
        st.dataframe(pd.DataFrame(edge_rows).head(500), use_container_width=True, hide_index=True)

with tabs[4]:
    if graph.number_of_nodes():
        entity = st.selectbox("Entity to investigate", sorted(map(str, graph.nodes)))
        direction = st.radio("Trace direction", ["backward", "forward"], horizontal=True, format_func=lambda v: "Backward · possible causes" if v == "backward" else "Forward · possible impact")
        depth = st.slider("Maximum hops", 1, 8, 4)
        result = trace_entity(graph, entity, direction=direction, max_depth=depth)
        st.write(f"**Related entities:** {len(result['entities'])} · **Evidence events:** {len(result['events'])}")
        trace_df = pd.DataFrame(result["events"])
        if not trace_df.empty:
            st.dataframe(trace_df, use_container_width=True, hide_index=True)
            st.download_button("Export trace evidence CSV", trace_df.to_csv(index=False).encode(), f"{direction}_trace.csv", "text/csv")
        else:
            st.info("No linked events were returned for this entity and direction.")
    else:
        st.info("No graph entities are available.")

with tabs[5]:
    if techniques:
        st.dataframe(pd.DataFrame(techniques), use_container_width=True, hide_index=True, column_config={"mitre_url": st.column_config.LinkColumn("MITRE ATT&CK reference")})
    else:
        st.info("No candidate ATT&CK mappings matched the configured rules.")
    st.caption("Mappings are event-linked hypotheses. Validate the original event and surrounding context before assigning a technique.")

with tabs[6]:
    st.subheader("Saved investigation history")
    current_status = connection_status()
    if not current_status["connected"]:
        st.warning("Persistent history requires MongoDB. The current analysis remains available above, but past runs cannot be loaded until MongoDB connects.")
        st.code("# Start MongoDB with Docker\ndocker compose up -d mongo\n\n# Then refresh this page", language="bash")
    else:
        try:
            history = list_runs(limit=100)
            st.write(f"**{len(history)}** saved investigation(s)")
            if history:
                hist_df = pd.DataFrame([{
                    "id": r.get("id"), "created_at": r.get("created_at"), "scenario": r.get("scenario"),
                    "events": r.get("event_count"), "flagged": r.get("flagged_count"),
                    "nodes": r.get("node_count"), "edges": r.get("edge_count"), "threshold": r.get("threshold")
                } for r in history])
                hquery = st.text_input("Filter saved investigations", placeholder="scenario name or run ID")
                if hquery:
                    hm = hist_df.astype(str).apply(lambda col: col.str.contains(hquery, case=False, regex=False)).any(axis=1)
                    hist_df = hist_df[hm]
                st.dataframe(hist_df, use_container_width=True, hide_index=True)
                available_runs = {f"{r.get('created_at')} · {r.get('scenario')} · {r.get('id')}" : r for r in history}
                selected_run_label = st.selectbox("Open saved result", list(available_runs.keys()))
                selected_run = available_runs[selected_run_label]
                st.json({"scenario": selected_run.get("scenario"), "metrics": selected_run.get("metrics"), "summary": selected_run.get("summary")})
                st.download_button("Download saved summary JSON", json.dumps(selected_run, indent=2, default=str).encode(), "saved_investigation.json", "application/json")
                st.markdown("#### Search all stored event evidence")
                db_query = st.text_input("Search MongoDB event history", placeholder="event ID, host, process, detail, reason", key="db_event_query")
                selected_db_run = st.selectbox("Search scope", ["All saved runs"] + [f"{r.get('scenario')} · {r.get('id')}" for r in history], key="db_run_scope")
                scope_id = None if selected_db_run == "All saved runs" else selected_db_run.rsplit(" · ", 1)[-1]
                if st.button("Search stored evidence", key="search_db_evidence"):
                    try:
                        hits = search_events(db_query, run_id=scope_id, limit=500)
                        st.session_state.db_search_hits = hits
                    except Exception as exc:
                        st.error(f"MongoDB search failed: {exc}")
                hits = st.session_state.get("db_search_hits", [])
                if hits:
                    st.write(f"**{len(hits)}** stored event(s) matched")
                    st.dataframe(pd.DataFrame(hits).drop(columns=["id"], errors="ignore"), use_container_width=True, hide_index=True)
                    st.download_button("Export stored search results", pd.DataFrame(hits).to_csv(index=False).encode(), "stored_evidence_search.csv", "text/csv", key="export_db_search")
            else:
                st.info("No saved runs yet. Analyze a bundled dataset or upload a CSV while MongoDB is running; each unique scenario/threshold combination is saved once.")
        except Exception as exc:
            st.error(f"Could not load history: {exc}")

with tabs[7]:
    st.subheader("Evaluation metrics")
    st.json(metrics)
    st.caption("Time-to-insight is not estimated. Measure it in a controlled investigation task and record the observed value separately.")
    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = Path(temp_dir) / "legacy_report.md"
        generate_report(input_name, metrics, paths, techniques, report_path)
        st.download_button("Download detailed technical report", report_path.read_bytes(), "technical_incident_report.md", "text/markdown")
    st.download_button("Download metrics JSON", json.dumps(metrics, indent=2, default=str).encode(), "metrics.json", "application/json")
    st.download_button("Download scored events CSV", df.to_csv(index=False).encode(), "scored_events.csv", "text/csv", key="metrics_export_events")
    st.download_button("Download candidate paths JSON", json.dumps(paths, indent=2, default=str).encode(), "candidate_paths.json", "application/json")
