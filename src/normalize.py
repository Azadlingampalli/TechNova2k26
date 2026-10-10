import pandas as pd
ALIASES={"event_id":["event_id","id","log_id"],"timestamp":["timestamp","time","datetime","@timestamp"],"source_entity":["source_entity","source","src","actor","user","src_ip"],"target_entity":["target_entity","target","dst","object","destination","dst_ip","file","path"],"event_type":["event_type","event","action","activity","operation","type"],"host":["host","hostname","computer","device","endpoint"],"process_id":["process_id","pid"],"parent_process_id":["parent_process_id","ppid"],"details":["details","message","description","command"],"label":["label","ground_truth","is_attack","attack_label"]}
def normalize_frame(frame):
 if frame is None or frame.empty: raise ValueError('Input CSV has no rows')
 out=pd.DataFrame(index=frame.index); lookup={str(c).strip().lower():c for c in frame.columns}
 for field, aliases in ALIASES.items():
  col=next((lookup[a] for a in aliases if a in lookup),None); out[field]=frame[col] if col is not None else ''
 if out.timestamp.astype(str).str.strip().eq('').all(): out['timestamp']=pd.date_range('2026-10-01',periods=len(out),freq='min').astype(str)
 out['timestamp']=pd.to_datetime(out.timestamp,errors='coerce',utc=True); fallback=pd.Timestamp('2026-10-01',tz='UTC')
 for i in out.index[out.timestamp.isna()]: out.loc[i,'timestamp']=fallback+pd.Timedelta(minutes=int(i))
 for f in ['event_id','source_entity','target_entity','event_type','host','process_id','parent_process_id','details']:
  out[f]=out[f].fillna('').astype(str).str.strip()
 out['event_id']=out.event_id.where(out.event_id.ne(''),[f'evt-{i+1:07d}' for i in range(len(out))])
 out['source_entity']=out.source_entity.where(out.source_entity.ne(''),'unknown_source'); out['target_entity']=out.target_entity.where(out.target_entity.ne(''),'unknown_target')
 out['event_type']=out.event_type.where(out.event_type.ne(''),'unknown_event').str.lower().str.replace(' ','_',regex=False)
 out['label']=out.label.astype(str).str.lower().isin(['1','true','attack','malicious','yes'])
 return out.sort_values(['timestamp','event_id']).reset_index(drop=True)
