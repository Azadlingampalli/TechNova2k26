import networkx as nx
def build_graph(df):
 g=nx.MultiDiGraph()
 for _,r in df.iterrows():
  u,v=str(r.source_entity),str(r.target_entity); g.add_node(u,entity_type='entity'); g.add_node(v,entity_type='entity')
  g.add_edge(u,v,key=str(r.event_id),event_id=str(r.event_id),source_entity=u,target_entity=v,timestamp=r.timestamp,event_type=str(r.event_type),host=str(r.host),anomaly_score=float(r.anomaly_score),suspicious=bool(r.is_suspicious),label=bool(r.label),details=str(r.details),reasons=str(r.reasons))
 return g
def reduce_graph(g,df,threshold=.28):
 keep=set(df.loc[df.anomaly_score>=threshold,'event_id'].astype(str)); endpoints=set()
 for u,v,k,d in g.edges(keys=True,data=True):
  if str(d['event_id']) in keep: endpoints.update([u,v])
 # Keep one-hop context edges touching suspicious endpoints.
 for u,v,k,d in g.edges(keys=True,data=True):
  if u in endpoints or v in endpoints: keep.add(str(d['event_id']))
 out=nx.MultiDiGraph()
 for u,v,k,d in g.edges(keys=True,data=True):
  if str(d['event_id']) in keep: out.add_node(u,**g.nodes[u]); out.add_node(v,**g.nodes[v]); out.add_edge(u,v,key=k,**d)
 return out,keep
