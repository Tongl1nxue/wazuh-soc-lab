#!/usr/bin/env bash
# Read-only inventory. Run inside the Ubuntu lab guest; no sudo or installs.
# Missing components are recorded and are not deployment failures at this stage.
set -u
export LC_ALL=C

check() {
  printf '\n[%s]\n' "$1"
  shift
  "$@"
  local result=$?
  printf '[exit=%s]\n' "$result"
}

check time date -Is
check os cat /etc/os-release
check architecture uname -m
check memory free -h
check disk df -h / /var
check cpu nproc
check addresses ip -br address
check routes ip route
check services systemctl is-active ssh nginx wazuh-agent
check log-files ls -l /var/log/auth.log /var/log/nginx/access.log
check map-count sysctl vm.max_map_count
printf '\nInventory finished. Review each exit code; this is not a deployment pass.\n'
