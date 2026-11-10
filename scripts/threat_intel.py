"""Enrich Wazuh alert snapshots. Network lookups require explicit --online."""
import argparse
from contextlib import closing
from datetime import timezone
from email.utils import parsedate_to_datetime
import http.client
from ipaddress import IPv6Address, ip_address, ip_network
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlencode


PRIVATE = Path(__file__).resolve().parents[1] / 'local-evidence' / 'threat-intel'
PROVIDERS = {'ip': 'abuseipdb', 'hash': 'virustotal'}
KEYS = {'abuseipdb': 'ABUSEIPDB_API_KEY', 'virustotal': 'VIRUSTOTAL_API_KEY'}
# Conservatively exclude transition and special-purpose ranges across Python versions.
SPECIAL = tuple(map(ip_network, ('192.0.0.0/24', '192.88.99.0/24', '64:ff9b::/96',
                                '64:ff9b:1::/48', '2001::/23', '2002::/16', '3fff::/20')))


def reference(ref, src=None, hash_value=None):
    return {'alert_id': str(ref['event_id']), 'rule_id': str(ref['rule_id']),
            'index': ref['index'], 'document_id': ref['document_id'],
            'ip': src, 'hash': hash_value}


def from_search(response):
    page = response['hits']
    total = page['total']
    count = len(page['hits'])
    complete = total == count if isinstance(total, int) else total == {'value': count, 'relation': 'eq'}
    if response.get('timed_out') or response.get('_shards', {}).get('failed') or not complete:
        raise ValueError('Search snapshot incomplete; export a complete alert page first')
    for hit in page['hits']:
        src = hit['_source']
        data = src.get('data', {})
        fim = src.get('syscheck', {})
        file_hash = None
        # In this deployment, deletion can still include the prior hash under *_after.
        # Use that alert for cleanup evidence, not for a second lookup of the same file.
        if fim.get('event') != 'deleted':
            hashes = (fim.get(algorithm + '_after') for algorithm in ('sha256', 'sha1', 'md5'))
            file_hash = next((h for h in hashes if normalize('hash', h)[0]), None)
        yield reference({'event_id': src['id'], 'rule_id': src['rule']['id'],
                         'index': hit['_index'], 'document_id': hit['_id']},
                        data.get('srcip') or data.get('src_ip'), file_hash)


def alerts(snapshot):
    if 'suricata_eve' in snapshot:
        yield reference(snapshot['wazuh_eve_alert'], snapshot['suricata_eve']['source_ip'])
        yield reference(snapshot['wazuh_nginx_alert'])
    elif 'events' in snapshot and 'native_rule_ids' in snapshot:
        for event in snapshot['events']:
            for ref in event['alerts']:
                yield reference(ref, event['source_ip'])
    elif 'ssh_alerts' in snapshot and 'web_alerts' in snapshot:
        yield from from_search(snapshot['ssh_alerts'])
        yield from from_search(snapshot['web_alerts'])
    elif 'hits' in snapshot:
        yield from from_search(snapshot)
    else:
        raise ValueError('Unsupported Wazuh alert snapshot shape')


def normalize(kind, value):
    if kind == 'hash':
        if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', value):
            return None, 'invalid_indicator'
        return value.lower(), None
    try:
        if not isinstance(value, str) or '%' in value:
            raise ValueError('Invalid source IP')
        address = ip_address(value)
    except ValueError:
        return None, 'invalid_indicator'
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (not address.is_global or address.is_multicast or address.is_reserved
            or any(address in network for network in SPECIAL)):
        return str(address), 'skipped_non_public'
    return str(address), None


def request(host, path, headers, timeout):
    # Fixed HTTPS endpoints, no redirects, and no credential-bearing response logs.
    connection = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        connection.request('GET', path, headers={'Accept': 'application/json', **headers})
        response = connection.getresponse()
        body = response.read(1_048_577) if response.status == 200 else b''
        return response.status, response.getheader('Retry-After'), body
    finally:
        connection.close()


def summary(kind, value, body):
    if len(body) > 1_048_576:
        raise ValueError('Provider response exceeds limit')
    data = json.loads(body)['data']
    if kind == 'ip':
        if ip_address(data['ipAddress']) != ip_address(value):
            raise ValueError('Provider returned a different IP')
        fields = {key: data[key] for key in ('abuseConfidenceScore', 'totalReports')}
        fields['lastReportedAt'] = data.get('lastReportedAt')
        fields['report_window_days'] = 90
        return fields
    attrs = data['attributes']
    algorithm = {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(value)]
    if attrs[algorithm].lower() != value:
        raise ValueError('Provider returned a different file hash')
    counts = attrs['last_analysis_stats']
    return {'last_analysis_date': attrs.get('last_analysis_date'),
            'last_analysis_stats': {k: counts[k] for k in ('malicious', 'suspicious', 'harmless', 'undetected')}}


def retry_at(header, now):
    try:
        if header and header.isdecimal():
            return now + max(60, int(header))
        if header:
            stamp = parsedate_to_datetime(header)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return max(now + 60, stamp.timestamp())
    except (ValueError, OverflowError):
        pass
    return now + 300


class Lookup:
    def __init__(self, db=None, keys=None, max_queries=5, transport=request, now=time.time):
        self.db = db
        self.keys = keys or {}
        self.remaining = max_queries
        self.transport = transport
        self.now = now
        if db is not None:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS cache (
                    provider TEXT, indicator TEXT, expires REAL, result TEXT,
                    PRIMARY KEY (provider, indicator));
                CREATE TABLE IF NOT EXISTS cooldown (provider TEXT PRIMARY KEY, until REAL);
            ''')

    def lookup(self, kind, value):
        provider = PROVIDERS[kind]
        indicator, reason = normalize(kind, value)
        base = {'kind': kind, 'indicator': indicator, 'provider': provider}
        if reason:
            return {**base, 'status': reason}
        if self.db is None:
            return {**base, 'status': 'offline'}
        now = self.now()
        cached = self.db.execute('SELECT result FROM cache WHERE provider=? AND indicator=? AND expires>?',
                                 (provider, indicator, now)).fetchone()
        if cached:
            return {**base, **json.loads(cached[0]), 'lookup_source': 'cache'}
        key = self.keys.get(provider)
        if not key:
            return {**base, 'status': 'missing_key'}
        cooling = self.db.execute('SELECT until FROM cooldown WHERE provider=? AND until>?',
                                  (provider, now)).fetchone()
        if cooling:
            return {**base, 'status': 'provider_cooldown', 'retry_after_unix': cooling[0]}
        if self.remaining <= 0:
            return {**base, 'status': 'budget_exhausted'}
        self.remaining -= 1
        result = self.fetch(kind, indicator, key, now)
        if result['status'] in ('success', 'not_found'):
            ttl = 86400 if result['status'] == 'success' else 21600
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?)',
                                (provider, indicator, now + ttl, json.dumps(result)))
        elif result['status'] == 'rate_limited':
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO cooldown VALUES (?, ?)',
                                (provider, result['retry_after_unix']))
        return {**base, **result, 'lookup_source': 'api'}

    def fetch(self, kind, value, key, now):
        if kind == 'ip':
            host = 'api.abuseipdb.com'
            path = '/api/v2/check?' + urlencode({'ipAddress': value, 'maxAgeInDays': 90})
            headers = {'Key': key}
        else:
            host = 'www.virustotal.com'
            path = '/api/v3/files/' + value
            headers = {'x-apikey': key}
        try:
            status, after, body = self.transport(host, path, headers, 8)
        except TimeoutError:
            return {'status': 'timeout'}
        except (OSError, http.client.HTTPException):
            return {'status': 'network_error'}
        if status == 200:
            try:
                return {'status': 'success', 'observed_at_unix': now, 'result': summary(kind, value, body)}
            except (ValueError, KeyError, TypeError, AttributeError):
                return {'status': 'invalid_response'}
        if status == 404 and kind == 'hash':
            return {'status': 'not_found', 'observed_at_unix': now}
        if status == 429:
            return {'status': 'rate_limited', 'retry_after_unix': retry_at(after, now)}
        return {'status': 'auth_error' if status in (401, 403) else 'http_error', 'http_status': status}


def enrich(paths, engine):
    seen = set()
    for path in paths:
        snapshot = json.loads(path.read_bytes())
        for row in alerts(snapshot):
            key = (row['index'], row['document_id'])
            if key in seen:
                continue
            seen.add(key)
            indicators = [(kind, row.pop(kind)) for kind in PROVIDERS]
            results = [engine.lookup(kind, value) for kind, value in indicators if value is not None]
            yield {**row, 'input': path.name, 'run_id': snapshot.get('run_id'),
                   'lookups': results or [{'status': 'no_indicator'}]}


def run(args, engine):
    if args.input:
        return {'mode': 'online' if args.online else 'offline', 'source': 'wazuh_snapshots',
                'alerts': list(enrich(args.input, engine))}
    kind, value = args.sample
    return {'mode': 'online' if args.online else 'offline', 'source': 'independent_public_sample',
            'sample_source': args.sample_source, 'lookups': [engine.lookup(kind, value)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--input', type=Path, action='append')
    inputs.add_argument('--sample', nargs=2, metavar=('KIND', 'INDICATOR'))
    parser.add_argument('--sample-source', help='Source URL or citation for the independent public sample')
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--max-queries', type=int, default=5)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.sample and (args.sample[0] not in PROVIDERS or not args.sample_source):
        parser.error('--sample requires ip or hash, a value and --sample-source')
    if args.max_queries < 1:
        parser.error('--max-queries must be at least 1')
    if args.online:
        PRIVATE.mkdir(parents=True, exist_ok=True)
        file = PRIVATE/'credentials.json'
        local = json.loads(file.read_bytes()) if file.exists() else {}
        keys = {name: os.environ.get(variable) or local.get(variable) for name, variable in KEYS.items()}
        with closing(sqlite3.connect(PRIVATE/'cache.sqlite3')) as db:
            report = run(args, Lookup(db, keys, args.max_queries))
    else:
        report = run(args, Lookup())
    result = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding='utf-8')
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
