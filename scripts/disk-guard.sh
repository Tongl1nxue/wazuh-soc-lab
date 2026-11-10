#!/usr/bin/env bash
# Dedicated VM only: stop event ingestion at 85% disk use; never delete evidence.
set -eu
used=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [ "$used" -ge 85 ]; then
  logger -t soc-disk-guard "Disk at ${used}%; stopping Wazuh manager ingestion; export evidence and inspect disk before restarting."
  cd /opt/soc-lab/wazuh-docker/single-node
  docker compose -f compose.lab.yml stop wazuh.manager
fi
