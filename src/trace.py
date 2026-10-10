import networkx as nx

def candidate_paths(df, max_events=12, gap_seconds=21600):
    """Group suspicious events into reviewable, time-bounded entity-linked candidates."""
    rows = df[df.is_suspicious].sort_values("timestamp")
    groups, current, entities, last = [], [], set(), None
    for _, row in rows.iterrows():
        event = row.to_dict()
        involved = {str(event["source_entity"]), str(event["target_entity"])}
        close = last is None or (row.timestamp - last).total_seconds() <= gap_seconds
        if current and (not entities.intersection(involved) or not close):
            groups.append(current)
            current, entities = [], set()
            last = None
        current.append(event)
        entities.update(involved)
        last = row.timestamp
        if len(current) >= max_events:
            groups.append(current)
            current, entities, last = [], set(), None
    if current:
        groups.append(current)
    paths = []
    for i, events in enumerate(groups, 1):
        score = min(1.0, sum(float(e["anomaly_score"]) for e in events) / len(events)
                    + min(len(events), 5) * .04)
        paths.append({
            "path_id": f"path-{i:03d}", "score": round(score, 3),
            "event_count": len(events), "start": str(events[0]["timestamp"]),
            "end": str(events[-1]["timestamp"]),
            "entities": sorted({str(e[k]) for e in events
                                for k in ("source_entity", "target_entity")}),
            "events": events,
        })
    return sorted(paths, key=lambda path: path["score"], reverse=True)

def trace_entity(graph, entity, direction="backward", max_depth=4):
    """Return upstream/downstream graph entities and their original event evidence."""
    if entity not in graph:
        return {"entity": entity, "direction": direction, "entities": [], "events": []}
    if direction == "backward":
        related = nx.ancestors(graph, entity)
    elif direction == "forward":
        related = nx.descendants(graph, entity)
    else:
        raise ValueError("direction must be 'backward' or 'forward'")
    # Bound trace breadth using shortest directed distance from/to the seed.
    if direction == "backward":
        distances = nx.single_source_shortest_path_length(graph.reverse(copy=False), entity, cutoff=max_depth)
    else:
        distances = nx.single_source_shortest_path_length(graph, entity, cutoff=max_depth)
    nodes = set(distances)
    edges = []
    for u, v, key, data in graph.edges(keys=True, data=True):
        if u in nodes and v in nodes:
            if direction == "backward" and distances.get(u, max_depth+1) <= max_depth and distances.get(v, max_depth+1) <= max_depth:
                edges.append(data)
            elif direction == "forward" and u in nodes and v in nodes:
                edges.append(data)
    events = []
    for edge in edges:
        events.append({
            "event_id": edge.get("event_id", ""),
            "timestamp": str(edge.get("timestamp", "")),
            "event_type": edge.get("event_type", ""),
            "source_entity": edge.get("source_entity", ""),
            "target_entity": edge.get("target_entity", ""),
            "host": edge.get("host", ""),
            "details": edge.get("details", ""),
            "anomaly_score": edge.get("anomaly_score", 0),
            "reasons": edge.get("reasons", ""),
        })
    events.sort(key=lambda e: e["timestamp"])
    return {"entity": entity, "direction": direction, "entities": sorted(nodes), "events": events}
