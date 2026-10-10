from pathlib import Path
from collections import Counter
import html
import json
import re


def _safe(value):
    return html.escape(str(value if value is not None else ""))


def summarize_incident(name, df, metrics, paths, techniques, threshold=0.28):
    """Create a deterministic, evidence-grounded narrative without using labels."""
    flagged = df[df["anomaly_score"] >= threshold].copy() if len(df) else df.copy()
    total, count = len(df), len(flagged)
    pct = (count / total * 100) if total else 0.0
    hosts = sorted({str(x) for x in flagged.get("host", []) if str(x).strip() and str(x).lower() != "nan"})
    reasons = []
    for value in flagged.get("reasons", []):
        reasons.extend(r.strip() for r in str(value).split(";") if r.strip() and r.strip() != "No strong heuristic matched")
    top_reasons = [r for r, _ in Counter(reasons).most_common(4)]
    top = flagged.sort_values("anomaly_score", ascending=False).head(10) if count else flagged
    first = str(flagged.timestamp.min()) if count else "Not available"
    last = str(flagged.timestamp.max()) if count else "Not available"
    high = int((flagged["anomaly_score"] >= 0.70).sum()) if count else 0

    if not count:
        issue = ("No events crossed the configured suspicious-score threshold. This does not prove the environment is clean; "
                 "the threshold and detection rules may miss activity.")
        severity = "No candidate alert"
        next_step = "Review time range and source coverage, then validate the detector with a known test scenario."
    else:
        reasons_lower = " ".join(top_reasons).lower()
        if "ransomware" in reasons_lower or "ransom" in reasons_lower or "encryption" in reasons_lower:
            issue = ("Possible ransomware-like or file-encryption activity was observed. Treat this as a triage lead until "
                     "file-operation and process evidence confirm the behavior.")
        elif "credential" in reasons_lower or "authentication" in reasons_lower:
            issue = ("Possible authentication or credential-access activity was observed. Verify account activity, source hosts, "
                     "and process context before concluding an account was compromised.")
        elif "web" in reasons_lower:
            issue = ("Possible suspicious web-server activity was observed. Check uploaded files, web-server process lineage, "
                     "and subsequent network or file activity.")
        elif "external" in reasons_lower or "destination" in reasons_lower:
            issue = ("Potentially unusual outbound communication was observed. A connection by itself does not establish "
                     "command-and-control or data exfiltration.")
        else:
            issue = ("The detector identified events with suspicious indicators that warrant investigation. The current evidence "
                     "is insufficient to declare a confirmed intrusion.")
        severity = "High-priority review" if high else "Investigation recommended"
        next_step = ("Start with the highest-scoring evidence events, trace their entities backward for possible causes and "
                     "forward for potential impact, then validate each finding against original logs.")

    return {
        "scenario": str(name), "issue": issue, "severity": severity,
        "events_analyzed": total, "events_flagged": count, "flagged_percent": round(pct, 2),
        "top_reasons": top_reasons, "hosts_involved": hosts[:20], "first_flagged": first,
        "last_flagged": last, "high_score_events": high, "candidate_path_count": len(paths),
        "candidate_attack_mappings": len(techniques), "node_reduction_pct": metrics.get("node_reduction_pct"),
        "edge_reduction_pct": metrics.get("edge_reduction_pct"),
        "attack_event_recall": metrics.get("attack_event_recall"), "next_step": next_step,
        "limitations": [
            "These are rule-based candidate findings, not proof of compromise.",
            "Entity relationships reflect log records and do not automatically prove causation.",
            "ATT&CK mappings are hypotheses and require analyst validation.",
            "Time-to-insight is not reported unless measured in a controlled task."
        ],
        "top_events": [
            {"event_id": str(r.event_id), "timestamp": str(r.timestamp), "event_type": str(r.event_type),
             "host": str(r.host), "source_entity": str(r.source_entity), "target_entity": str(r.target_entity),
             "score": round(float(r.anomaly_score), 3), "reasons": str(r.reasons), "details": str(r.details)}
            for _, r in top.iterrows()
        ]
    }


def generate_html_report(name, df, metrics, paths, techniques, threshold=0.28):
    """Return standalone HTML with clickable links from findings to log evidence rows."""
    summary = summarize_incident(name, df, metrics, paths, techniques, threshold)

    def anchor(event_id):
        return "event-" + re.sub(r"[^A-Za-z0-9_.:-]", "_", str(event_id))

    evidence_links = []
    for ev in summary["top_events"]:
        evidence_links.append(
            f'<li><a href="#{_safe(anchor(ev["event_id"]))}">{_safe(ev["event_id"])}</a> '
            f'({_safe(ev["timestamp"])}): {_safe(ev["event_type"])} on {_safe(ev["host"])} — '
            f'score {ev["score"]}; {_safe(ev["reasons"])}. {_safe(ev["details"][:350])}</li>'
        )
    if not evidence_links:
        evidence_links = ['<li>No events crossed the configured threshold.</li>']

    tech_html = []
    for t in techniques:
        eid = str(t.get("event_id", ""))
        tech_html.append(
            f'<li><a href="#{_safe(anchor(eid))}">{_safe(eid or "event unavailable")}</a>: '
            f'<a href="{_safe(t.get("mitre_url", "https://attack.mitre.org/"))}">{_safe(t.get("technique_id"))} — {_safe(t.get("technique"))}</a>. '
            f'{_safe(t.get("evidence_rationale", ""))} Evidence: {_safe(t.get("evidence", ""))}</li>'
        )
    if not tech_html:
        tech_html = ['<li>No ATT&CK mapping rules matched the flagged evidence.</li>']

    event_rows = []
    for _, r in df.sort_values("timestamp").iterrows():
        eid = str(r.event_id)
        event_rows.append(
            f'<tr id="{_safe(anchor(eid))}"><td>{_safe(eid)}</td><td>{_safe(r.timestamp)}</td>'
            f'<td>{_safe(r.event_type)}</td><td>{_safe(r.host)}</td><td>{_safe(r.source_entity)} → {_safe(r.target_entity)}</td>'
            f'<td>{float(r.anomaly_score):.3f}</td><td>{_safe(r.reasons)}</td><td>{_safe(r.details)}</td></tr>'
        )
    hosts = ", ".join(summary["hosts_involved"]) or "Not identified"
    reasons = ", ".join(summary["top_reasons"]) or "No strong heuristic matched"
    recall = summary["attack_event_recall"]
    recall_text = "Not available" if recall is None else f"{float(recall)*100:.1f}%"
    limitations = ''.join('<li>' + _safe(x) + '</li>' for x in summary['limitations'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RansomTrace AI Incident Summary — {_safe(name)}</title><style>
body{{font:16px/1.55 system-ui,Arial,sans-serif;max-width:1200px;margin:30px auto;padding:0 18px;color:#172033}}h1,h2{{line-height:1.2}}.box{{border:1px solid #cbd5e1;border-radius:10px;padding:16px;margin:16px 0}}.severity{{font-weight:700}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #cbd5e1;padding:7px;text-align:left;vertical-align:top}}th{{background:#f1f5f9}}tr:target{{background:#fff2bf}}a{{color:#075985}}.muted{{color:#475569}}</style></head><body>
<h1>RansomTrace AI — Incident Summary</h1><p class="muted">Scenario: {_safe(name)} · Generated from the currently selected log dataset</p>
<div class="box"><p class="severity">Triage status: {_safe(summary['severity'])}</p><h2>What appears to be the issue?</h2><p>{_safe(summary['issue'])}</p><p><b>Why it was flagged:</b> {_safe(reasons)}</p><p><b>Hosts in flagged events:</b> {_safe(hosts)}</p><p><b>Flagged time window:</b> {_safe(summary['first_flagged'])} — {_safe(summary['last_flagged'])}</p><p><b>Recommended next step:</b> {_safe(summary['next_step'])}</p></div>
<h2>At-a-glance</h2><ul><li>Events analyzed: {summary['events_analyzed']}</li><li>Events flagged: {summary['events_flagged']} ({summary['flagged_percent']}%)</li><li>Candidate paths: {summary['candidate_path_count']}</li><li>Candidate ATT&amp;CK mappings: {summary['candidate_attack_mappings']}</li><li>Node reduction: {_safe(summary['node_reduction_pct'])}%</li><li>Edge reduction: {_safe(summary['edge_reduction_pct'])}%</li><li>Attack-event recall: {_safe(recall_text)}</li></ul>
<h2>Key findings and clickable evidence</h2><p>Choose an event ID to jump directly to that event's row in the evidence table.</p><ol>{''.join(evidence_links)}</ol>
<h2>Candidate MITRE ATT&amp;CK mappings</h2><ul>{''.join(tech_html)}</ul>
<h2>Complete log evidence</h2><p class="muted">Each row has a stable anchor. Use your browser's find function to search an event ID. The table contains normalized log fields and detector explanations.</p>
<table><thead><tr><th>Event ID</th><th>Timestamp</th><th>Type</th><th>Host</th><th>Source → target</th><th>Score</th><th>Reasons</th><th>Log details</th></tr></thead><tbody>{''.join(event_rows)}</tbody></table>
<h2>Limitations</h2><ul>{limitations}</ul><p class="muted">This report is a triage aid, not a confirmed incident verdict. Validate against original telemetry and analyst context.</p></body></html>'''


def generate_report(name, metrics, paths, techniques, out):
    lines = [f'# RansomTrace AI Incident Report — {name}', '', '## Summary',
             f"- Events analyzed: **{metrics['events']}**",
             f"- Events flagged: **{metrics['detected_events']}**",
             f'- Candidate paths: **{len(paths)}**',
             '- Findings are triage suggestions and require analyst validation.', '',
             '## Metrics', '```json', json.dumps(metrics, indent=2), '```', '', '## Candidate paths']
    if not paths:
        lines.append('No candidate paths produced.')
    for p in paths:
        lines += [f"### {p['path_id']} (score {p['score']})", f"- Time: {p['start']} — {p['end']}",
                  f"- Entities: {', '.join(p['entities'])}", '- Evidence:']
        for e in p['events']:
            lines.append(f"  - `{e['event_id']}` | {e['timestamp']} | {e['event_type']} | `{e['source_entity']}` → `{e['target_entity']}` | score {e['anomaly_score']} | {e['reasons']}")
    lines += ['', '## Candidate MITRE ATT&CK mappings']
    lines += [f"- **[{t['technique_id']} — {t['technique']}]({t.get('mitre_url', 'https://attack.mitre.org/')})** — event `{t.get('event_id', 'unknown')}` at {t.get('timestamp', 'unknown')}: {t['evidence_rationale']} Evidence: {t.get('evidence', '')}" for t in techniques] or ['No mapping rule matched.']
    lines += ['', '## Limitations', '- Rule-based detector; false positives and false negatives are expected.',
               '- Candidate paths are entity-linked chronological groupings, not causal proof.',
               '- ATT&CK mappings are hypotheses.', '- Reduction is not guaranteed to preserve every attack path.',
               '- Time-to-insight must be measured in a controlled analyst study.']
    Path(out).write_text('\n'.join(lines), encoding='utf-8')
