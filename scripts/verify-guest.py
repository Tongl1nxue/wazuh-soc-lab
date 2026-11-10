"""Read-only infrastructure checks in the dedicated guest. No incident simulation."""
import base64
import datetime
import json
import re
from pathlib import Path
import ssl
import subprocess
import time
import urllib.request

ROOT = Path('/opt/soc-lab')
STACK = ROOT / 'wazuh-docker/single-node'
creds = json.loads((ROOT / 'credentials.json').read_text())
ctx = ssl.create_default_context(cafile=str(STACK / 'config/wazuh_indexer_ssl_certs/root-ca.pem'))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))


def get(url):
    req = urllib.request.Request(url)
    auth = base64.b64encode(('admin:' + creds['admin']).encode()).decode()
    req.add_header('Authorization', 'Basic ' + auth)
    with opener.open(req, timeout=15) as response:
        return response.status, response.read().decode()


def command(args):
    result = subprocess.run(args, cwd=STACK, capture_output=True, text=True)
    return {'exit': result.returncode, 'output': result.stdout.strip(), 'stderr': result.stderr.strip()}


result = {'time': datetime.datetime.now().astimezone().isoformat()}
for attempt in range(40):
    try:
        status, body = get('https://wazuh.indexer:9200/_cluster/health')
        health = json.loads(body)
        result['indexer'] = {'http': status, 'status': health['status'], 'nodes': health['number_of_nodes']}
        status, body = get('https://wazuh.dashboard:8443/api/status')
        result['dashboard'] = {'http': status, 'status': json.loads(body).get('status', {}).get('overall')}
        break
    except Exception as exc:
        if attempt == 39:
            result['readiness_error'] = str(exc)
        else:
            print(f'Waiting for SIEM readiness: {type(exc).__name__}', flush=True)
            time.sleep(5)
result['containers'] = command(['docker', 'compose', '-f', 'compose.lab.yml', 'ps', '--format', 'json'])
if result['containers']['exit']==0:
    result['containers']['services']=[{key: row[key] for key in ['Name','Image','State','Status','Ports']}
        for row in (json.loads(line) for line in result['containers']['output'].splitlines() if line)]
    del result['containers']['output']
result['agent'] = command(['docker', 'compose', '-f', 'compose.lab.yml', 'exec', '-T', 'wazuh.manager', '/var/ossec/bin/agent_control', '-l'])
for attempt in range(20):
    if re.search(r'Name:\s*soc-ubuntu,.*\bActive\b', result['agent']['output']):
        break
    time.sleep(5)
    result['agent'] = command(['docker', 'compose', '-f', 'compose.lab.yml', 'exec', '-T', 'wazuh.manager', '/var/ossec/bin/agent_control', '-l'])
result['agent_connected'] = bool(re.search(r'Name:\s*soc-ubuntu,.*\bActive\b', result['agent']['output']))
try:
    with opener.open('http://127.0.0.1:8080/', timeout=10) as response:
        result['nginx_http'] = response.status
except Exception as exc:
    result['nginx_error'] = str(exc)
result['guest_services'] = command(['systemctl', 'is-active', 'ssh', 'nginx', 'docker', 'wazuh-agent'])
result['disk'] = command(['df', '-h', '/'])
result['memory'] = command(['free', '-h'])
result['listeners'] = command(['ss', '-lnt'])
result['versions'] = command(['docker', 'version', '--format', '{{.Server.Version}}'])
(ROOT / 'infrastructure-verification.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
raise SystemExit(1 if 'readiness_error' in result or result['guest_services']['exit'] or not result['agent_connected'] or result.get('nginx_http') != 200 else 0)
