"""Capture a bounded SSH key-auth experiment on the dedicated SOC guest only."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import uuid


spec = importlib.util.spec_from_file_location('pipeline', Path(__file__).with_name('phase1-log-pipeline.py'))
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)

AUTH = re.compile(
    r'\bsshd\[(?P<pid>\d+)\]: (?P<outcome>Failed|Accepted) publickey for '
    r'(?P<user>\w+) from (?P<ip>127\.0\.0\.1) port (?P<port>\d+) ssh2(?:\b|:)'
)
PLAN = [
    ('A', 'wrong', 'failure'), ('A', 'wrong', 'failure'), ('A', 'wrong', 'failure'),
    ('B', 'original', 'success'), ('A', 'original', 'success'),
    ('A', 'original', 'success'), ('A', 'original', 'failure'),
    ('A', 'replacement', 'success'),
]


def command(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=10)


def exercise(root, users, created):
    for user in users.values():
        command(['useradd', '-M', '-N', '-d', '/nonexistent', '-s', '/bin/sh', user])
        created.append(user)
    # Traverse only; all private key files retain ssh-keygen's restrictive mode.
    root.chmod(0o711)
    for key in ('original', 'wrong', 'replacement'):
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / key)])

    def authorize(user, key):
        path = root / (user + '.authorized')
        path.write_bytes((root / (key + '.pub')).read_bytes())
        path.chmod(0o644)

    for user in users.values():
        authorize(user, 'original')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    host_key = Path('/etc/ssh/ssh_host_ed25519_key')
    fields = host_key.with_suffix('.pub').read_text().split()
    (root / 'known_hosts').write_text(f'[127.0.0.1]:{port} {fields[0]} {fields[1]}\n')
    config = root / 'sshd_config'
    config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root}/%u.authorized
AllowUsers {' '.join(users.values())}
PermitRootLogin no
UsePAM yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
DisableForwarding yes
PermitTTY no
ForceCommand /usr/bin/true
LogLevel VERBOSE
''')
    command(['/usr/sbin/sshd', '-t', '-f', str(config)])
    with subprocess.Popen(['/usr/sbin/sshd', '-D', '-f', str(config)]) as daemon:
        try:
            for _ in range(20):
                if daemon.poll() is not None:
                    raise RuntimeError('Temporary sshd exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Temporary sshd did not listen')

            for step, (account, key, expected) in enumerate(PLAN, 1):
                if step == 7:
                    authorize(users['A'], 'replacement')
                result = command(['ssh', '-F', '/dev/null', '-p', str(port), '-i', str(root / key),
                    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                    '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={root / "known_hosts"}',
                    '-o', 'PreferredAuthentications=publickey', '-o', 'ConnectTimeout=3',
                    users[account] + '@127.0.0.1', 'true'], check=False)
                denied = result.returncode == 255 and 'Permission denied (publickey)' in result.stderr
                if not (result.returncode == 0 if expected == 'success' else denied):
                    raise RuntimeError(f'SSH step {step} did not produce the expected client result')
        finally:
            if daemon.poll() is None:
                daemon.terminate()
            daemon.wait(timeout=5)


def documents(response):
    page = response['hits']
    if (response.get('timed_out') or response['_shards']['failed'] or page['total']['relation'] != 'eq'
            or page['total']['value'] != len(page['hits'])):
        raise RuntimeError('Incomplete SSH index response')
    return page['hits']


def snapshot(run_id, users):
    aliases = {name: alias for alias, name in users.items()}
    query = {'size': 100, 'track_total_hits': True, 'query': {'bool': {'filter': [
        {'term': {'location': '/var/log/auth.log'}},
        {'bool': {'should': [{'match_phrase': {'full_log': user}} for user in users.values()],
                  'minimum_should_match': 1}},
    ]}}, 'sort': [{'timestamp': 'asc'}]}
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        archives = documents(pipeline.query('wazuh-archives-*', query))
        alerts = documents(pipeline.query('wazuh-alerts-*', query))
        alert_refs = {}
        for hit in alerts:
            source = hit['_source']
            alert_refs.setdefault(source['full_log'], []).append({
                'event_id': source['id'], 'rule_id': source['rule']['id'],
                'index': hit['_index'], 'document_id': hit['_id'],
            })
        events = []
        connections = {}
        for hit in archives:
            source = hit['_source']
            log = source['full_log']
            match = AUTH.search(log)
            if not match or match['user'] not in aliases:
                continue
            identity = (match['pid'], match['port'])
            connection = connections.setdefault(identity, f'conn-{len(connections) + 1:02d}')
            events.append({'host': 'LAB-UBUNTU', 'source_ip': match['ip'],
                'account': aliases[match['user']], 'connection': connection,
                'timestamp': source['timestamp'],
                'outcome': 'success' if match['outcome'] == 'Accepted' else 'failure',
                'archive': {'index': hit['_index'], 'document_id': hit['_id']},
                'alerts': alert_refs.get(log, []),
            })
        distinct = {(row['connection'], row['outcome']): row for row in reversed(events)}
        timeline = list(reversed(distinct.values()))
        if ([(row['account'], row['outcome']) for row in timeline] == [(a, c) for a, _, c in PLAN]
                and all(row['alerts'] for row in timeline)):
            return {'run_id': run_id, 'source': 'live_wazuh_index_queries',
                'events': events, 'archive_hit_count': len(archives),
                'alert_hit_count': len(alerts), 'temporary_accounts_removed': True,
                'native_rule_ids': sorted({hit['_source']['rule']['id'] for hit in alerts})}
        time.sleep(2)
    raise RuntimeError(f'SSH timeline incomplete: {len(timeline)} auth events, {len(alerts)} alerts')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['verify'])
    parser.parse_args()
    run_id = 'socseq' + uuid.uuid4().hex[:10]
    users = {alias: run_id + alias.lower() for alias in ('A', 'B')}
    created = []
    with tempfile.TemporaryDirectory(prefix='soc-sequence-', dir='/run') as directory:
        try:
            exercise(Path(directory), users, created)
        finally:
            removed = [command(['userdel', user], check=False).returncode == 0 for user in created]
            if not all(removed):
                raise RuntimeError('Could not remove every temporary test account')
    print(json.dumps(snapshot(run_id, users), indent=2))


if __name__ == '__main__':
    main()
