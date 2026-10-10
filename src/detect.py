import re
RULES=[(r'failed_login|login_failed|auth_failure|brute',.25,'Authentication failures'),(r'privilege|sudo|admin|role_change|elevation',.28,'Privilege-related activity'),(r'powershell|encoded|base64|cmd\.exe|bash -c|script',.25,'Script/command execution'),(r'credential|password_dump|lsass|token',.35,'Credential-access indicator'),(r'archive|compress|staging|sensitive|payroll|student_records|customer_db',.25,'Sensitive data/staging indicator'),(r'\bexternal\b|\bunusual\b|\brare\b|unknown_ip|\btor\b',.25,'Unusual destination'),(r'ransom|encrypt|shadow_copy|mass_file',.40,'Possible ransomware behavior'),(r'webshell|upload|unexpected_file|php',.28,'Suspicious web activity')]
COMMON={'file_read','file_write','process_start','network_connection','http_request','login_success','dns_query'}
def score_events(df):
 out=df.copy(); scores=[]; reasons=[]
 for _,r in out.iterrows():
  text=' '.join(str(r.get(k,'')) for k in ['event_type','source_entity','target_entity','host','details']).lower(); s=.05; why=[]
  for pat,w,label in RULES:
   if re.search(pat,text): s+=w; why.append(label)
  if str(r.event_type).lower() not in COMMON|{'unknown_event',''}: s+=.08; why.append('Uncommon event type')
  # Labels are deliberately not used to score, to avoid evaluation leakage.
  scores.append(min(s,1.0)); reasons.append('; '.join(dict.fromkeys(why)) if why else 'No strong heuristic matched')
 out['anomaly_score']=scores; out['reasons']=reasons; out['is_suspicious']=out.anomaly_score>=.28
 return out
