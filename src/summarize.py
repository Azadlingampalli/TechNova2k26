"""Deterministic, evidence-linked natural-language incident summaries.

This local summarizer does not call an external LLM. Every claim is generated
from the scored event table and links back to event IDs for analyst validation.
"""
from __future__ import annotations
import html
from collections import Counter
import pandas as pd


def build_summary(scenario: str, df: pd.DataFrame, metrics: dict, paths: list, techniques: list) -> dict:
    flagged = df[df["is_suspicious"]].copy() if "is_suspicious" in df else df.iloc[0:0]
    flagged = flagged.sort_values("anomaly_score", ascending=False)
    total = len(df)
    nflag = len(flagged)
    hosts = sorted(set(flagged.host.astype(str)) - {"", "nan"})
    types = Counter(flagged.event_type.astype(str))
    start = df.timestamp.min().isoformat() if total else "Unknown"
    end = df.timestamp.max().isoformat() if total else "Unknown"
    top_events = []
    for _, row in flagged.head(12).iterrows():
        top_events.append({
            "event_id": str(row.event_id), "timestamp": row.timestamp.isoformat() if hasattr(row.timestamp, "isoformat") else str(row.timestamp),
            "score": round(float(row.anomaly_score), 3), "event_type": str(row.event_type),
            "host": str(row.host), "source": str(row.source_entity), "target": str(row.target_entity),
            "details": str(row.details), "reasons": str(row.reasons),
        })
    if nflag:
        severity = "High" if float(flagged.anomaly_score.max()) >= .70 or nflag >= max(10, int(total*.05)) else ("Medium" if float(flagged.anomaly_score.max()) >= .45 else "Low")
        lead = top_events[0]
        overview = (f"RansomTrace AI reviewed {total:,} events from {scenario} covering {start} through {end}. "
                    f"It flagged {nflag:,} events ({(nflag/total*100 if total else 0):.1f}%) for analyst review. "
                    f"The highest-scoring event is {lead['event_id']} on host {lead['host'] or 'unknown host'} "
                    f"(score {lead['score']:.2f}), associated with: {lead['reasons']}. "
                    "These are rule-based triage findings, not a confirmed breach verdict.")
    else:
        severity = "No flagged events"
        overview = f"RansomTrace AI reviewed {total:,} events from {scenario} covering {start} through {end} and found no events above the configured threshold. This does not prove the environment is benign."
    recommendations = []
    combined = " ".join(flagged.get("reasons", pd.Series(dtype=str)).astype(str)).lower()
    if "credential" in combined or "authentication" in combined:
        recommendations.append("Review authentication logs and credential-use history for the referenced accounts; rotate credentials only after validating the incident and preserving evidence.")
    if "ransomware" in combined or "ransom" in combined or "file" in combined:
        recommendations.append("Inspect high-volume file writes and modifications on the affected host; verify backup health and isolate affected systems only under your incident-response procedure.")
    if "network" in combined or "destination" in combined or "external" in combined:
        recommendations.append("Validate outbound destinations against approved network records and preserve relevant DNS, proxy, firewall, and flow logs.")
    if "privilege" in combined or "script" in combined or "web" in combined:
        recommendations.append("Review parent/child process context, command-line details, account privileges, and recent changes on the affected host.")
    recommendations += [
        "Validate each candidate against the original event record and nearby benign context before declaring an incident.",
        "Preserve original logs and timestamps; document any filtering, normalization, and graph-reduction choices."
    ]
    return {
        "scenario": scenario, "severity": severity, "overview": overview, "event_count": total,
        "flagged_count": nflag, "flagged_pct": round(100*nflag/total, 2) if total else 0,
        "time_start": start, "time_end": end, "hosts": hosts, "event_type_counts": dict(types),
        "candidate_path_count": len(paths), "technique_count": len(techniques),
        "top_events": top_events, "recommendations": list(dict.fromkeys(recommendations)),
        "metrics": metrics,
        "caveats": ["Severity is a triage priority, not a confirmed incident classification.",
                    "Scoring is based on transparent heuristics and may produce false positives or false negatives.",
                    "ATT&CK mappings are candidate matches; a keyword or single event is not proof of a technique.",
                    "The current local summarizer is deterministic and does not use an external language model."],
    }


def summary_markdown(summary: dict, techniques: list) -> str:
    lines = [f"# RansomTrace AI — Incident Summary: {summary['scenario']}", "",
             f"**Triage priority:** {summary['severity']}  ",
             f"**Coverage:** {summary['time_start']} → {summary['time_end']}  ",
             f"**Events reviewed:** {summary['event_count']:,}  ",
             f"**Events flagged:** {summary['flagged_count']:,} ({summary['flagged_pct']}%)", "",
             "## Executive summary", summary["overview"], "",
             "## What needs attention"]
    if summary["top_events"]:
        for e in summary["top_events"]:
            evidence_link = f"[Open evidence `{e['event_id']}`](#evidence-{e['event_id']})"
            lines += [f"### {e['event_id']} — {e['event_type']} (score {e['score']:.2f})",
                      f"- **Time:** {e['timestamp']}", f"- **Host:** {e['host'] or 'Unknown'}",
                      f"- **Relationship:** `{e['source']}` → `{e['target']}`",
                      f"- **Why flagged:** {e['reasons']}", f"- **Details:** {e['details'] or 'No details supplied'}",
                      f"- **Evidence:** {evidence_link}", f"<a id=\"evidence-{html.escape(e['event_id'])}\"></a>", ""]
    else:
        lines.append("No event crossed the configured suspiciousness threshold. Review coverage and threshold before drawing conclusions.")
    lines += ["## Candidate MITRE ATT&CK mappings"]
    if techniques:
        for t in techniques:
            lines.append(f"- [{t.get('technique_id')} — {t.get('technique')}]({t.get('mitre_url', 'https://attack.mitre.org/')}) — evidence event `{t.get('event_id', 'unknown')}`; {t.get('evidence_rationale', 'Review source evidence.')}")
    else:
        lines.append("No candidate mapping matched the configured rules.")
    lines += ["", "## Recommended next steps"]
    lines += [f"{i}. {item}" for i, item in enumerate(summary["recommendations"], 1)]
    lines += ["", "## Metrics"]
    for k, v in summary["metrics"].items():
        lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
    lines += ["", "## Important limitations"] + [f"- {x}" for x in summary["caveats"]]
    lines += ["", "## Evidence appendix", "The evidence IDs below refer to the original uploaded or bundled log records. Search the History & Log Search page by event ID to inspect full fields.", ""]
    lines += [f"- `{e['event_id']}` — {e['timestamp']} — {e['event_type']} — {e['source']} → {e['target']}" for e in summary["top_events"]]
    return "\n".join(lines)
