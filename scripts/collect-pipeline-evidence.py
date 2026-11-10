"""Copy private proof locally; publish only explicitly safe verification fields."""
import json
import re
from pathlib import Path
from lab_transport import ROOT, PRIVATE, run

target=PRIVATE/'phase1-pipeline'
target.mkdir(exist_ok=True)
for filename in ['audit.json','latest-summary.json']:
    result=run('sudo cat /opt/soc-lab/phase1-pipeline/'+filename)
    if result.returncode:
        raise SystemExit('Evidence collection failed; remote file not ready')
    (target/filename).write_bytes(result.stdout)
summary=json.loads((target/'latest-summary.json').read_text())
token=summary['run_id']
if not re.fullmatch(r'soc-pipeline-[a-f0-9]{12}',token):
    raise SystemExit('Unexpected run ID')
result=run('sudo cat /opt/soc-lab/phase1-pipeline/'+token+'.json')
if result.returncode:
    raise SystemExit('Raw proof could not be collected')
(target/(token+'.json')).write_bytes(result.stdout)
public=ROOT/'evidence/pipeline'
public.mkdir(parents=True,exist_ok=True)
allowed=['run_id','http_status','nginx_archive_matches','ssh_success_matches',
         'nginx_event_ids','nginx_index_ids','ssh_alert_ids','passed']
(public/'verification.json').write_text(json.dumps({key:summary[key] for key in allowed},indent=2))
print('Raw proof retained privately; allowlisted verification summary saved to evidence/pipeline/verification.json')
