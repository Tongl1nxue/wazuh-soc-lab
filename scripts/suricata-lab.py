"""Manage the isolated Suricata loopback sensor and verify its Wazuh evidence chain."""
import argparse
from decimal import Decimal
import http.client
import importlib.util
import json
from pathlib import Path
import shutil
import time
import uuid


spec = importlib.util.spec_from_file_location('pipeline', Path(__file__).with_name('phase1-log-pipeline.py'))
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)

STATE = pipeline.ROOT/'suricata'
AGENT = Path('/var/ossec/etc/ossec.conf')
SENSOR = 'soc-suricata.service'
EVE = Path('/var/log/suricata/soc-lab/eve.json')
NGINX = '/var/log/nginx/soc_access.log'
CONFIG = Path('/etc/soc-suricata/soc-suricata.yaml')
BLOCK = f'''  <!-- soc-suricata-loopback -->
  <localfile>
    <log_format>json</log_format>
    <location>{EVE}</location>
  </localfile>
'''
PATHS = ('/index.html', '/.env.example', '/docs/.env-guide', '/.env')
SID = '1000001'


def service(*args, check=True):
    return pipeline.cmd(['systemctl', *args], check=check)


def configure():
    if not shutil.which('suricata'):
        raise RuntimeError('Install the Ubuntu Suricata package before configuring the sensor')
    if service('is-active', '--quiet', 'suricata.service', check=False).returncode == 0:
        raise RuntimeError('Default Suricata service is active; inspect before enabling the lab sensor')
    STATE.mkdir(mode=0o700, exist_ok=True)
    backup = STATE/'ossec.conf.before-suricata'
    if not backup.exists():
        shutil.copy2(AGENT, backup)
    prior = AGENT.read_text()
    if str(EVE) in prior and BLOCK not in prior:
        raise RuntimeError('EVE input already exists outside the managed block')
    for destination in (CONFIG, CONFIG.with_suffix('.rules'),
                        Path('/etc/systemd/system')/SENSOR, Path('/etc/logrotate.d/soc-suricata')):
        name = destination.name if destination.suffix else 'soc-suricata.logrotate'
        pipeline.cmd(['install', '-D', '-m', '0644', str(Path('/tmp')/name), str(destination)])
    EVE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    pipeline.cmd(['suricata', '-T', '-c', str(CONFIG)])
    pipeline.cmd(['logrotate', '-d', '/etc/logrotate.d/soc-suricata'])
    service('daemon-reload')
    added = BLOCK not in prior
    was_active = service('is-active', '--quiet', SENSOR, check=False).returncode == 0
    try:
        if added:
            if '</ossec_config>' not in prior:
                raise RuntimeError('Agent config has no ossec_config closing tag')
            AGENT.write_text(prior.replace('</ossec_config>', BLOCK+'</ossec_config>', 1))
        pipeline.cmd(['/var/ossec/bin/wazuh-logcollector', '-t'])
        service('enable', SENSOR)
        service('restart', SENSOR)
        service('restart', 'wazuh-agent.service')
        service('is-active', '--quiet', 'wazuh-agent.service', SENSOR)
    except Exception:
        if added:
            AGENT.write_text(prior)
            service('restart', 'wazuh-agent.service', check=False)
        if not was_active:
            service('disable', '--now', SENSOR, check=False)
        raise
    print('Suricata configuration validated; loopback sensor and Wazuh Agent started.')


def restore():
    prior = AGENT.read_text()
    if BLOCK in prior:
        AGENT.write_text(prior.replace(BLOCK, '', 1))
        try:
            pipeline.cmd(['/var/ossec/bin/wazuh-logcollector', '-t'])
            service('restart', 'wazuh-agent.service')
        except Exception:
            AGENT.write_text(prior)
            service('restart', 'wazuh-agent.service', check=False)
            raise
    service('disable', '--now', SENSOR)
    print('Lab sensor disabled and EVE input removed; config backup and evidence retained.')


def request(uri):
    connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=5)
    try:
        connection.request('GET', uri, headers={'Connection': 'close'})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def hits(index, marker):
    # Suricata's built-in alert rule uses no_full_log. Keep the Nginx text
    # search and also match structured EVE URIs in either index.
    selectors = [{'match_phrase': {'full_log': marker}}]
    selectors.extend({'match_phrase': {'data.http.url': f'{path}?soc_run={marker}'}} for path in PATHS)
    body = {'size': 40, 'track_total_hits': True, 'query': {'bool': {'filter': [
        {'terms': {'location': [str(EVE), NGINX]}},
        {'bool': {'should': selectors, 'minimum_should_match': 1}},
    ]}}}
    result = pipeline.query(index, body)
    page = result['hits']
    if (result.get('timed_out') or result['_shards']['failed'] or page['total']['relation'] != 'eq'
            or page['total']['value'] != len(page['hits'])):
        raise RuntimeError('Incomplete experiment index query')
    return page['hits']


def reference(hit):
    event = hit['_source']
    rule = event.get('rule', {})
    return {'index': hit['_index'], 'document_id': hit['_id'], 'event_id': event['id'],
            'timestamp': event['timestamp'], 'rule_id': rule.get('id'), 'rule_level': rule.get('level')}


def eve_events(marker):
    rows = []
    for path in (EVE.with_name('eve.json.1'), EVE):
        if not path.exists():
            continue
        with path.open() as log:
            for line in log:
                if marker in line and line.endswith('\n'):
                    rows.append(json.loads(line))
    return rows


def verify():
    service('is-active', '--quiet', SENSOR)
    marker = 'soc-ids-' + uuid.uuid4().hex[:12]
    requests = {f'{path}?soc_run={marker}': None for path in PATHS}
    for uri in requests:
        requests[uri] = request(uri)
    positive = f'/.env?soc_run={marker}'
    if requests[positive] != 404 or requests[f'/index.html?soc_run={marker}'] != 200:
        raise RuntimeError('Nginx baseline or probe response differed from the planned test')
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        eve = eve_events(marker)
        archives = hits('wazuh-archives-*', marker)
        alerts = hits('wazuh-alerts-*', marker)
        nginx = {h['_source']['data']['url']: h for h in archives if h['_source']['location'] == NGINX}
        eve_archive = [h for h in archives if h['_source']['location'] == str(EVE)]
        eve_alert = [h for h in alerts if h['_source']['location'] == str(EVE)]
        web_alert = [h for h in alerts if h['_source']['location'] == NGINX
                     and h['_source']['rule']['id'] == '100110']
        if (set(nginx) == set(requests) and eve and eve_archive and eve_alert and web_alert):
            break
        time.sleep(2)
    else:
        raise RuntimeError(f'Evidence incomplete: EVE={len(eve)}, nginx={len(nginx)}, '
                           f'EVE archives={len(eve_archive)}, EVE alerts={len(eve_alert)}, Web={len(web_alert)}')

    if not len(eve) == len(eve_archive) == len(eve_alert) == len(web_alert) == 1:
        raise RuntimeError('Expected one positive in each detector; inspect the lab outputs')
    [event] = eve
    if (event['event_type'] != 'alert' or event['alert']['action'] != 'allowed'
            or str(event['alert']['signature_id']) != SID or event['http']['url'] != positive
            or event['src_ip'] != '127.0.0.1' or event['dest_ip'] != '127.0.0.1'
            or event['dest_port'] != 8080 or event['in_iface'] != 'lo'):
        raise RuntimeError('EVE event did not match the loopback IDS experiment')
    for hit in (eve_archive[0], eve_alert[0]):
        data = hit['_source']['data']
        # The Wazuh JSON decoder can serialize the integer with a decimal suffix.
        if (data['http']['url'] != positive or Decimal(str(data['flow_id'])) != event['flow_id']
                or str(data['alert']['signature_id']) != SID or data['timestamp'] != event['timestamp']):
            raise RuntimeError('Wazuh document does not refer to the same EVE event')
    if eve_alert[0]['_source']['rule']['id'] != '86601' or web_alert[0]['_source']['data']['url'] != positive:
        raise RuntimeError('Unexpected Wazuh rule or Web alert URI')
    for uri, status in requests.items():
        if int(nginx[uri]['_source']['data']['id']) != status:
            raise RuntimeError('Nginx archive status did not match the client response')

    memory = service('show', '--property=MemoryCurrent', '--value', SENSOR).stdout.strip()
    evidence = {'run_id': marker, 'mode': 'passive_ids', 'capture_interface': 'lo',
        'suricata_version': pipeline.cmd(['suricata', '-V']).stdout.strip(),
        'suricata_memory_bytes': int(memory) if memory.isdigit() else None,
        'eve_bytes': EVE.stat().st_size,
        'requests': [{'uri': uri, 'status': status, 'nginx_archive': reference(nginx[uri]),
                      'suricata_match': uri == positive, 'wazuh_web_match': uri == positive}
                     for uri, status in requests.items()],
        'suricata_eve': {'timestamp': event['timestamp'], 'flow_id': event['flow_id'],
            'source_ip': event['src_ip'], 'destination_ip': event['dest_ip'],
            'destination_port': event['dest_port'], 'uri': positive, 'signature_id': event['alert']['signature_id'],
            'action': event['alert']['action']},
        'wazuh_eve_archive': reference(eve_archive[0]), 'wazuh_eve_alert': reference(eve_alert[0]),
        'wazuh_nginx_alert': reference(web_alert[0]), 'passed': True}
    pipeline.save_json(STATE/(marker+'.json'), evidence)
    print(json.dumps(evidence, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['configure', 'verify', 'restore'])
    {'configure': configure, 'verify': verify, 'restore': restore}[parser.parse_args().mode]()


if __name__ == '__main__':
    main()
