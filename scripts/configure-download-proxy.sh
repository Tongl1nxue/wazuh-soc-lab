#!/usr/bin/env bash
# Use an SSH reverse tunnel to the user's existing Windows HTTP proxy.
set -euo pipefail
[[ $EUID -eq 0 && $(hostname) == soc-ubuntu ]]
python3 - <<'PY'
import json
from pathlib import Path
p=Path('/etc/docker/daemon.json')
data=json.loads(p.read_text()) if p.exists() else {}
data['proxies']={'http-proxy':'http://127.0.0.1:18080',
                 'https-proxy':'http://127.0.0.1:18080',
                 'no-proxy':'localhost,127.0.0.1,wazuh.manager,wazuh.indexer,wazuh.dashboard'}
p.write_text(json.dumps(data,indent=2)+'\n')
PY
systemctl restart docker
curl --proxy http://127.0.0.1:18080 -sS -o /dev/null -w 'Official registry HTTP status: %{http_code}\n' https://registry-1.docker.io/v2/
