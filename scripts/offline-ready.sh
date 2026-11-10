#!/usr/bin/env bash
# Remove the temporary download proxy dependency, then verify a daemon restart.
set -euo pipefail
[[ $EUID -eq 0 && $(hostname) == soc-ubuntu ]]
python3 - <<'PY'
import json
from pathlib import Path
p=Path('/etc/docker/daemon.json')
data=json.loads(p.read_text())
data.pop('proxies',None)
p.write_text(json.dumps(data,indent=2)+'\n')
PY
systemctl restart docker
python3 /tmp/verify-guest.py
