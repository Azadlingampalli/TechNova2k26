import argparse,json
from pathlib import Path
import pandas as pd
from src.normalize import normalize_frame
from src.detect import score_events
from src.graph import build_graph,reduce_graph
from src.trace import candidate_paths
from src.attack_mapping import map_attack_techniques
from src.evaluate import evaluate
from src.report import generate_report
def run(inp,out,threshold=.28,name=None,analyst_time_to_insight_seconds=None):
 out=Path(out); out.mkdir(parents=True,exist_ok=True); df=score_events(normalize_frame(pd.read_csv(inp))); df['is_suspicious']=df.anomaly_score>=threshold
 g=build_graph(df); rg,kept=reduce_graph(g,df,threshold); paths=candidate_paths(df); tech=map_attack_techniques(df[df.is_suspicious]); metrics=evaluate(df,g,rg,kept_event_ids=kept,analyst_time_to_insight_seconds=analyst_time_to_insight_seconds)
 df.to_csv(out/'scored_events.csv',index=False); pd.DataFrame([{k:p[k] for k in ['path_id','score','event_count','start','end']} for p in paths]).to_csv(out/'candidate_paths.csv',index=False)
 (out/'metrics.json').write_text(json.dumps(metrics,indent=2)); (out/'attack_mappings.json').write_text(json.dumps(tech,indent=2)); (out/'graph_summary.json').write_text(json.dumps({'original':{'nodes':g.number_of_nodes(),'edges':g.number_of_edges()},'reduced':{'nodes':rg.number_of_nodes(),'edges':rg.number_of_edges()},'kept_event_ids':sorted(kept)},indent=2))
 generate_report(name or Path(inp).stem,metrics,paths,tech,out/'incident_report.md'); print(json.dumps(metrics,indent=2)); return metrics
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',default='outputs/run'); p.add_argument('--threshold',type=float,default=.28); p.add_argument('--name'); p.add_argument('--time-to-insight-seconds',type=float,default=None,help='Measured analyst task time; do not estimate or invent this value'); a=p.parse_args(); run(a.input,a.output,a.threshold,a.name,a.time_to_insight_seconds)
