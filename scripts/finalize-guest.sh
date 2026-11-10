#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 && $(hostname) == soc-ubuntu ]]
if ! grep -q '127.0.0.1 wazuh.indexer wazuh.dashboard' /etc/hosts; then
  printf '\n127.0.0.1 wazuh.indexer wazuh.dashboard\n' >> /etc/hosts
fi
install -m 700 /tmp/disk-guard.sh /opt/soc-lab/disk-guard.sh
cat > /etc/systemd/system/soc-disk-guard.service <<'UNIT'
[Unit]
Description=Stop SOC ingestion before the lab disk fills
[Service]
Type=oneshot
ExecStart=/opt/soc-lab/disk-guard.sh
UNIT
cat > /etc/systemd/system/soc-disk-guard.timer <<'UNIT'
[Unit]
Description=Check SOC lab disk use every minute
[Timer]
OnBootSec=3min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now soc-disk-guard.timer
python3 /tmp/verify-guest.py
