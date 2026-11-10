"""Create a harmless local file and verify its Wazuh FIM hash and deletion alerts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import time
import uuid


spec = importlib.util.spec_from_file_location('pipeline', Path(__file__).with_name('phase1-log-pipeline.py'))
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
WATCH = pipeline.ROOT/'ti-fim'
STATE = pipeline.ROOT/'threat-intel'
CONFIG = Path('/var/ossec/etc/ossec.conf')
AGENT_LOG = Path('/var/ossec/logs/ossec.log')
ENTRY = f'    <directories realtime="yes" check_all="yes">{WATCH}</directories>\n'


def update(prior, replacement, wait_for_scan=False):
    offset = AGENT_LOG.stat().st_size
    CONFIG.write_text(replacement)
    try:
        pipeline.cmd(['/var/ossec/bin/wazuh-syscheckd', '-t'])
        pipeline.cmd(['systemctl', 'restart', 'wazuh-agent'])
        if wait_for_scan:
            for _ in range(60):
                with AGENT_LOG.open('rb') as stream:
                    stream.seek(offset if AGENT_LOG.stat().st_size >= offset else 0)
                    if b'File integrity monitoring scan ended.' in stream.read():
                        break
                time.sleep(1)
            else:
                raise RuntimeError('Agent FIM did not finish its initial scan')
    except Exception:
        CONFIG.write_text(prior)
        pipeline.cmd(['systemctl', 'restart', 'wazuh-agent'], check=False)
        raise


def configure():
    prior = CONFIG.read_text()
    if ENTRY not in prior:
        if str(WATCH) in prior or prior.count('  </syscheck>') != 1:
            raise RuntimeError('Unexpected Agent FIM configuration; inspect before changing it')
        STATE.mkdir(mode=0o700, exist_ok=True)
        WATCH.mkdir(mode=0o750, exist_ok=True)
        backup = STATE/'ossec.conf.before-fim'
        if not backup.exists():
            shutil.copy2(CONFIG, backup)
        update(prior, prior.replace('  </syscheck>', ENTRY+'  </syscheck>', 1), wait_for_scan=True)
    print('Dedicated real-time FIM directory is configured.')


def restore():
    prior = CONFIG.read_text()
    if ENTRY in prior:
        update(prior, prior.replace(ENTRY, '', 1))
    print('Lab FIM input removed. Agent backup and evidence retained.')


def find(path, event_type):
    query = {'size': 10, 'track_total_hits': True, 'query': {'bool': {'filter': [
        {'match_phrase': {'syscheck.path': str(path)}}, {'term': {'syscheck.event': event_type}},
    ]}}}
    for _ in range(40):
        result = pipeline.query('wazuh-alerts-*', query)
        page = result['hits']
        if result.get('timed_out') or result['_shards']['failed'] or page['total'] != {'value': len(page['hits']), 'relation': 'eq'}:
            raise RuntimeError('Incomplete FIM query')
        exact = [hit for hit in page['hits'] if hit['_source']['syscheck']['path'] == str(path)]
        if len(exact) == 1:
            hit = exact[0]
            source = hit['_source']
            syscheck = source['syscheck']
            return {'_index': hit['_index'], '_id': hit['_id'], '_source': {
                'id': source['id'], 'timestamp': source['timestamp'], 'rule': {'id': source['rule']['id']},
                'syscheck': {field: syscheck[field] for field in ('path', 'event', 'mode', 'sha256_after')
                             if field in syscheck},
            }}
        if exact:
            raise RuntimeError('Multiple FIM alerts for the same file and event type')
        time.sleep(2)
    raise RuntimeError('FIM alert not indexed for ' + event_type)


def verify():
    if ENTRY not in CONFIG.read_text() or WATCH.resolve() != WATCH:
        raise RuntimeError('Expected the dedicated local FIM directory')
    run_id = 'soc-fim-' + uuid.uuid4().hex[:12]
    path = WATCH/(run_id+'.txt')
    contents = f'Authorized SOC lab integrity verification {run_id}\n'.encode()
    digest = hashlib.sha256(contents).hexdigest()
    stream = path.open('xb')
    try:
        with stream:
            stream.write(contents)
        added = find(path, 'added')
        data = added['_source']
        if data['rule']['id'] != '554' or data['syscheck'].get('sha256_after') != digest:
            raise RuntimeError('Indexed FIM file hash or add rule differs from the experiment')
    finally:
        path.unlink()
    deleted = find(path, 'deleted')
    if deleted['_source']['rule']['id'] != '553':
        raise RuntimeError('Indexed FIM deletion rule differs from the experiment')
    evidence = {'run_id': run_id, 'source': 'real_harmless_local_file', 'local_sha256': digest,
        'file_removed': not path.exists(), 'timed_out': False, '_shards': {'failed': 0},
        'hits': {'total': {'value': 2, 'relation': 'eq'}, 'hits': [added, deleted]}}
    pipeline.save_json(STATE/(run_id+'.json'), evidence)
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['configure', 'verify', 'restore'])
    {'configure': configure, 'verify': verify, 'restore': restore}[parser.parse_args().mode]()
