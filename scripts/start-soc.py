"""Start only the dedicated SOC VM and keep its local SSH web tunnel open."""
import json
import socket
from pathlib import Path
import subprocess
import sys
import time
import webbrowser

root=Path(__file__).resolve().parents[1]
private=root/'local-evidence'
access=json.loads((private/'access.json').read_text(encoding='utf-8-sig'))
vmrun=Path('E:/vmware/vmrun.exe')
running=subprocess.run([str(vmrun),'list'],capture_output=True,text=True,check=True).stdout
if access['vmx'].lower() not in running.lower():
    subprocess.run([str(vmrun),'-T','ws','start',access['vmx'],'nogui'],check=True)
options=['ssh','-i',str(private/'soc_ed25519'),'-o','BatchMode=yes',
         '-o','UserKnownHostsFile='+str(private/'known_hosts'),'-o','ConnectTimeout=5',
         '-o','ServerAliveInterval=30']
target='soc@'+access['ip']
for attempt in range(36):
    status=subprocess.run(options+[target,'true'],capture_output=True)
    if status.returncode==0:
        break
    print('Waiting for Ubuntu SSH...',flush=True)
    time.sleep(5)
else:
    raise SystemExit('SSH unavailable. Inspect VMware and the IP in local-evidence/access.json.')
if '--shell' in sys.argv:
    raise SystemExit(subprocess.call(options+[target]))
print('Dashboard: https://localhost:8443\nNginx: http://localhost:18080',flush=True)
print('Keep this window open. Dashboard credentials: local-evidence/dashboard-login.txt',flush=True)
with socket.socket() as probe:
    if probe.connect_ex(('127.0.0.1',8443))==0:
        if (private/'web-tunnel.pid').exists():
            print('A local web tunnel is already running.',flush=True)
            if '--no-browser' not in sys.argv:
                webbrowser.open('https://localhost:8443')
            raise SystemExit(0)
        raise SystemExit('Local port 8443 is occupied; inspect the listener before continuing.')
tunnel = subprocess.Popen(options+['-o','ExitOnForwardFailure=yes','-N',
    '-L','127.0.0.1:8443:127.0.0.1:8443','-L','127.0.0.1:18080:127.0.0.1:8080',target])
try:
    if '--no-browser' not in sys.argv:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and tunnel.poll() is None:
            with socket.socket() as probe:
                probe.settimeout(0.2)
                ready = probe.connect_ex(('127.0.0.1',8443)) == 0
            if ready and tunnel.poll() is None:
                webbrowser.open('https://localhost:8443')
                break
            time.sleep(0.1)
    raise SystemExit(tunnel.wait())
finally:
    if tunnel.poll() is None:
        tunnel.terminate()
        tunnel.wait()
