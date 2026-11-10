"""Collect real detection evidence privately and export an allowlisted summary."""
import json
import re
from lab_transport import ROOT, PRIVATE, run

dest=PRIVATE/'detection-lab';dest.mkdir(exist_ok=True)
for name in ['audit.json','baseline.json','logtest.json','configuration.json','summary.json']:
    result=run('sudo cat /opt/soc-lab/detection-lab/'+name)
    if result.returncode:raise SystemExit('Evidence file not ready: '+name)
    (dest/name).write_bytes(result.stdout)
summary=json.loads((dest/'summary.json').read_text())
token=summary['run_id']
if not re.fullmatch('soc-detect-[a-f0-9]{12}',token):raise SystemExit('Invalid run identifier')
result=run('sudo cat /opt/soc-lab/detection-lab/'+token+'.json')
if result.returncode:raise SystemExit('Raw evidence unavailable')
(dest/(token+'.json')).write_bytes(result.stdout)
raw=json.loads(result.stdout)
public=ROOT/'evidence/detection';public.mkdir(parents=True,exist_ok=True)
(public/'verification.json').write_text(json.dumps(summary,indent=2))
tests=json.loads((dest/'logtest.json').read_text())
matrix={label:{path:{'rule_id':r['rule_id'],'exit':r['exit']} for path,r in cases.items()}
        for label,cases in tests.items()}
(public/'replay-matrix.json').write_text(json.dumps(matrix,indent=2))
events={}
for category in ['web_archives','web_alerts','ssh_archives','ssh_alerts']:
    events[category]=[]
    for hit in raw[category]['hits']['hits']:
        src=hit['_source'];rule=src.get('rule',{});data=src.get('data',{})
        events[category].append({'index_document_id':hit['_id'],'event_id':src.get('id'),
            'timestamp':src.get('timestamp'),'location':src.get('location'),
            'rule_id':rule.get('id'),'rule_level':rule.get('level'),
            'path':data.get('url'),'http_status':data.get('id') if category.startswith('web') else None})
(public/'events.json').write_text(json.dumps(events,indent=2))
result=run('sudo cat /opt/soc-lab/wazuh-docker/single-node/config/soc_lab/soc_web_rules.xml')
if result.returncode:raise SystemExit('Deployed rule source unavailable')
rules=ROOT/'config/rules';rules.mkdir(parents=True,exist_ok=True)
(rules/'soc_web_rules.xml').write_bytes(result.stdout)
print(json.dumps({'run_id':token,'passed':summary['passed'],
    'replay_rule_ids':matrix,'public_proof':'evidence/detection',
    'raw_proof':'local-evidence/detection-lab'},indent=2))
