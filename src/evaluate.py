def evaluate(df, g, rg, kept_event_ids=None, analyst_time_to_insight_seconds=None):
    lab = df.label.astype(bool)
    pred = df.is_suspicious.astype(bool)
    tp = int((lab & pred).sum())
    fp = int((~lab & pred).sum())
    fn = int((lab & ~pred).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    n0, n1 = g.number_of_nodes(), rg.number_of_nodes()
    e0, e1 = g.number_of_edges(), rg.number_of_edges()
    kept = set(map(str, kept_event_ids or []))
    attack_ids = set(df.loc[lab, "event_id"].astype(str))
    retained_attack_ids = attack_ids & kept
    return {
        "events": len(df),
        "ground_truth_attack_events": int(lab.sum()),
        "detected_events": int(pred.sum()),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "attack_event_recall": round(tp / int(lab.sum()), 4) if lab.sum() else None,
        "original_nodes": n0,
        "reduced_nodes": n1,
        "node_reduction_pct": round(100 * (n0 - n1) / n0, 2) if n0 else 0.0,
        "original_edges": e0,
        "reduced_edges": e1,
        "edge_reduction_pct": round(100 * (e0 - e1) / e0, 2) if e0 else 0.0,
        "attack_events_retained_in_reduced_graph": len(retained_attack_ids),
        "attack_event_retention_pct": round(100 * len(retained_attack_ids) / len(attack_ids), 2) if attack_ids else None,
        "retained_attack_event_ids": sorted(retained_attack_ids),
        "analyst_time_to_insight_seconds": analyst_time_to_insight_seconds,
        "time_to_insight_note": "Measure with a controlled analyst task; null means no user-study time was supplied.",
        "note": "Heuristic triage only; labels are used for evaluation, never for detector scoring."
    }
