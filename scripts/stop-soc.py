"""Gracefully power off only the dedicated SOC VM through SSH."""
import json
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parents[1]
private=root/'local-evidence'
access=json.loads((private/'access.json').read_text(encoding='utf-8-sig'))
result=subprocess.run(['ssh','-i',str(private/'soc_ed25519'),'-o','BatchMode=yes',
    '-o','UserKnownHostsFile='+str(private/'known_hosts'),'soc@'+access['ip'],
    'sudo shutdown -h now'])
print('Shutdown requested. Confirm VMware shows SOC-Ubuntu powered off.')
raise SystemExit(result.returncode)
