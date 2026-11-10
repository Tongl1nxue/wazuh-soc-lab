#!/usr/bin/env bash
# Dedicated SOC-Ubuntu only. Run as root. Does not generate incident evidence.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if [[ -n ${SOC_DOWNLOAD_PROXY:-} ]]; then
  export http_proxy="$SOC_DOWNLOAD_PROXY" https_proxy="$SOC_DOWNLOAD_PROXY"
  export no_proxy='localhost,127.0.0.1,wazuh.indexer,wazuh.manager,wazuh.dashboard'
fi
umask 077
[[ $EUID -eq 0 && $(hostname) == soc-ubuntu ]] || { echo 'Dedicated soc-ubuntu root session required'; exit 1; }
install -d -m 700 /opt/soc-lab
exec > >(tee -a /opt/soc-lab/deploy.log) 2>&1
trap 'echo "FAILED line=$LINENO; inspect /opt/soc-lab/deploy.log"' ERR
echo "Deployment started $(date -Is)"
if [[ ${1:-} != --resume-agent ]]; then
[[ $(df --output=avail -BG / | tail -1 | tr -dc 0-9) -ge 25 ]] || { echo 'Need >=25 GiB free before installing'; exit 1; }
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl gnupg git python3-yaml python3-bcrypt nginx rsyslog open-vm-tools
systemctl enable --now open-vm-tools rsyslog

# Install Docker from its official signed Ubuntu repository.
if ! docker compose version >/dev/null 2>&1; then
install -m 0755 -d /etc/apt/keyrings
curl --fail --retry 3 --retry-all-errors -L https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu jammy stable\n' > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
if [[ ! -f /etc/docker/daemon.json ]]; then
  printf '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}\n' > /etc/docker/daemon.json
fi
systemctl enable --now docker
printf 'vm.max_map_count=262144\n' > /etc/sysctl.d/99-soc-wazuh.conf
sysctl -p /etc/sysctl.d/99-soc-wazuh.conf

cd /opt/soc-lab
if [[ ! -d wazuh-docker/.git ]]; then
  git clone --depth 1 --branch v4.14.9 https://github.com/wazuh/wazuh-docker.git
fi
git -C wazuh-docker rev-parse HEAD > upstream-commit.txt
cd wazuh-docker/single-node
python3 - <<'PY'
from pathlib import Path
import bcrypt, json, secrets, string, yaml
secret_file=Path('/opt/soc-lab/credentials.json')
if secret_file.exists():
    creds=json.loads(secret_file.read_text())
else:
    alphabet=string.ascii_letters+string.digits
    creds={k: 'Aa1!'+''.join(secrets.choice(alphabet) for _ in range(28))
           for k in ['admin','kibanaserver','api']}
    secret_file.write_text(json.dumps(creds,indent=2)); secret_file.chmod(0o600)
compose=yaml.safe_load(Path('docker-compose.yml').read_text())
for name,service in compose['services'].items():
    # All SIEM access goes through loopback / SSH tunnels.
    ports={'wazuh.manager':['127.0.0.1:1514:1514','127.0.0.1:1515:1515','127.0.0.1:55000:55000'],
           'wazuh.indexer':['127.0.0.1:9200:9200'],
           'wazuh.dashboard':['127.0.0.1:8443:5601']}
    service['ports']=ports[name]
    env=service.get('environment',[])
    if isinstance(env,list):
        env=dict(item.split('=',1) for item in env)
    for key,kind in [('INDEXER_PASSWORD','admin'),('DASHBOARD_PASSWORD','kibanaserver'),('API_PASSWORD','api')]:
        if key in env: env[key]=creds[kind]
    # Preserve literal compose interpolation semantics for password values.
    service['environment']=env
    service['logging']={'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}
    service['restart']='unless-stopped'
Path('compose.lab.yml').write_text(yaml.safe_dump(compose,sort_keys=False))
internal_path=Path('config/wazuh_indexer/internal_users.yml')
users=yaml.safe_load(internal_path.read_text())
for name in list(users):
    if name not in ['_meta','admin','kibanaserver']: del users[name]
for name in ['admin','kibanaserver']:
    users[name]['hash']=bcrypt.hashpw(creds[name].encode(),bcrypt.gensalt(rounds=12)).decode()
internal_path.write_text(yaml.safe_dump(users,sort_keys=False))
dash=Path('config/wazuh_dashboard/wazuh.yml')
data=yaml.safe_load(dash.read_text())
for host in data['hosts']:
    for value in host.values(): value['password']=creds['api']
dash.write_text(yaml.safe_dump(data,sort_keys=False))
# Vulnerability feeds are outside the Linux/Web log monitoring project scope.
import re
manager=Path('config/wazuh_cluster/wazuh_manager.conf')
text=manager.read_text()
text=re.sub(r'(<vulnerability-detection>.*?<enabled>)yes(</enabled>)',r'\g<1>no\2',text,flags=re.S)
manager.write_text(text)
PY
docker compose -f compose.lab.yml config --quiet
if [[ ! -s config/wazuh_indexer_ssl_certs/root-ca.pem ]]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi
# Non-root indexer/dashboard users must be able to read bind-mounted configs.
chown -R 1000:1000 config
find config -type d -exec chmod 750 {} +
find config -type f -exec chmod 640 {} +
docker compose -f compose.lab.yml pull
[[ $(df --output=avail -BG / | tail -1 | tr -dc 0-9) -ge 8 ]] || { echo 'Less than 8 GiB free after image pull; not starting'; exit 1; }
docker compose -f compose.lab.yml up -d

# Lab web server: no external listeners, no vulnerable application required.
cat > /etc/nginx/sites-available/soc-lab <<'NGINX'
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    root /var/www/soc-lab;
    access_log /var/log/nginx/soc_access.log combined;
    error_log /var/log/nginx/soc_error.log;
    location / { try_files $uri $uri/ =404; }
}
NGINX
install -d /var/www/soc-lab
printf '<!doctype html><title>SOC local lab</title><h1>SOC local lab</h1>\n' > /var/www/soc-lab/index.html
chmod 755 /var/www/soc-lab
chmod 644 /var/www/soc-lab/index.html
[[ ! -L /etc/nginx/sites-enabled/default ]] || unlink /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/soc-lab /etc/nginx/sites-enabled/soc-lab
nginx -t
systemctl enable --now nginx
systemctl reload nginx
fi

# Signed agent package; the host agent reads Ubuntu logs, not container logs.
curl --fail --retry 3 -L https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /opt/soc-lab/wazuh-key.asc
gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg /opt/soc-lab/wazuh-key.asc
chmod 644 /usr/share/keyrings/wazuh.gpg
printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
WAZUH_MANAGER=127.0.0.1 WAZUH_AGENT_NAME=soc-ubuntu apt-get install -y wazuh-agent=4.14.9-1
apt-mark hold wazuh-agent
python3 - <<'PY'
from pathlib import Path
p=Path('/var/ossec/etc/ossec.conf')
s=p.read_text()
if '/var/log/nginx/soc_access.log' not in s:
    config='''  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/soc_access.log</location>
  </localfile>
'''
    s=s.replace('</ossec_config>',config+'</ossec_config>',1)
if '/var/log/auth.log' not in s:
    s=s.replace('</ossec_config>','''  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
</ossec_config>''',1)
p.write_text(s)
PY
systemctl daemon-reload
systemctl enable --now wazuh-agent
apt-get clean
journalctl --vacuum-size=100M
install -d /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/soc-lab.conf
systemctl restart systemd-journald
echo "Bootstrap finished $(date -Is); service readiness and ingestion still require verification."
cd /opt/soc-lab/wazuh-docker/single-node
docker compose -f compose.lab.yml ps
df -h /
free -h
