"""Collect private access details and verify the local SSH web tunnel."""
from pathlib import Path
import http.client
import json
import socket
import ssl
import subprocess
import time

root=Path(__file__).resolve().parents[1]
private=root/'local-evidence'
access=json.loads((private/'access.json').read_text(encoding='utf-8-sig'))
args=['ssh','-i',str(private/'soc_ed25519'),'-o','BatchMode=yes',
      '-o','UserKnownHostsFile='+str(private/'known_hosts')]
target='soc@'+access['ip']

def remote(command):
    return subprocess.run(args+[target,command],check=True,capture_output=True).stdout

# Secrets go directly to ignored local files, never to tool output.
credentials=json.loads(remote('sudo cat /opt/soc-lab/credentials.json'))
(private/'dashboard-login.txt').write_text('URL: https://localhost:8443\nUsername: admin\nPassword: '+credentials['admin']+'\n',encoding='utf-8')
(private/'root-ca.pem').write_bytes(remote('sudo cat /opt/soc-lab/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem'))
(private/'infrastructure-verification.json').write_bytes(remote('sudo cat /opt/soc-lab/infrastructure-verification.json'))
(private/'upstream-commit.txt').write_bytes(remote('sudo cat /opt/soc-lab/upstream-commit.txt'))
with socket.socket() as probe:
    already_running=probe.connect_ex(('127.0.0.1',8443))==0
if not already_running:
    with (private/'web-tunnel.err').open('wb') as errors:
        process=subprocess.Popen(args+['-o','ServerAliveInterval=30','-o','ExitOnForwardFailure=yes','-N',
            '-L','127.0.0.1:8443:127.0.0.1:8443','-L','127.0.0.1:18080:127.0.0.1:8080',target],
            stdout=subprocess.DEVNULL,stderr=errors,creationflags=subprocess.CREATE_NO_WINDOW)
    (private/'web-tunnel.pid').write_text(str(process.pid))
    time.sleep(2)
ctx=ssl.create_default_context(cafile=str(private/'root-ca.pem'))
# Wazuh's official certificate generator emits a legacy CA without keyUsage.
# Python 3.13+ enables STRICT by default; retain chain/signature verification
# while accepting this CA using the OpenSSL compatibility validation mode.
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
# The certificate is for wazuh.dashboard; the endpoint is our SSH localhost tunnel.
# Verify its issuing CA; host identity is already checked by SSH known_hosts.
ctx.check_hostname=False
connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ctx,timeout=15)
connection.request('GET','/')
response=connection.getresponse()
print('Local dashboard HTTP status:',response.status)
if response.status not in (200,302):
    raise SystemExit('Dashboard tunnel verification failed')
connection.close()
connection=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
connection.request('GET','/')
response=connection.getresponse()
print('Local Nginx HTTP status:',response.status)
if response.status!=200:
    raise SystemExit('Nginx tunnel verification failed')
connection.close()
manifest=json.loads((private/'vm-manifest.json').read_text(encoding='utf-8-sig'))
manifest['status']='infrastructure-verified'
(private/'vm-manifest.json').write_text(json.dumps(manifest,indent=2))
print('Private login details saved. No incident simulation or detection claim has been made.')
