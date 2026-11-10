"""Local tests with synthetic provider responses and real lab snapshots."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from threat_intel import Lookup, alerts, enrich


ROOT = Path(__file__).resolve().parents[1]
IP = '118.25.6.39'  # Public AbuseIPDB documentation example; never contacted by tests.
HASH = 'a' * 64  # Synthetic hash for response-shape tests.
KEYS = {'abuseipdb': 'UNIT_TEST', 'virustotal': 'UNIT_TEST'}


def response(body):
    return 200, None, json.dumps(body).encode()


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.transport = Mock(side_effect=AssertionError('Unexpected provider request'))
        self.now = 1700000000
        self.engine = Lookup(self.db, KEYS, transport=self.transport, now=lambda: self.now)

    def test_nonpublic_and_invalid_never_reach_transport_even_online(self):
        for ip in ('127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.1.1', '100.64.1.1',
                   '192.0.2.1', '192.0.0.9', '240.0.0.1', '224.0.0.1', '0.0.0.0',
                   '::1', 'fd00::1', 'fe80::1', '2001:db8::1', 'ff02::1', '::ffff:127.0.0.1'):
            with self.subTest(ip=ip):
                self.assertEqual(self.engine.lookup('ip', ip)['status'], 'skipped_non_public')
        self.assertEqual(self.engine.lookup('ip', '8.8.8.8/24')['status'], 'invalid_indicator')
        self.assertEqual(self.engine.lookup('hash', 'not-a-hash')['status'], 'invalid_indicator')
        self.transport.assert_not_called()

    def test_abuseipdb_zero_reports_uses_success_and_persistent_cache(self):
        self.transport.side_effect = None
        self.transport.return_value = response({'data': {'ipAddress': IP, 'abuseConfidenceScore': 0,
                                                          'totalReports': 0, 'lastReportedAt': None}})
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            path = Path(folder)/'cache.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                result = Lookup(db, KEYS, transport=self.transport, now=lambda: self.now).lookup('ip', IP)
            self.transport.assert_called_once_with('api.abuseipdb.com', f'/api/v2/check?ipAddress={IP}&maxAgeInDays=90',
                                                   {'Key': 'UNIT_TEST'}, 8)
            self.assertEqual(result['status'], 'success')
            self.assertEqual(result['result']['totalReports'], 0)
            with closing(sqlite3.connect(path)) as db:
                cached = Lookup(db, KEYS, transport=self.transport, now=lambda: self.now).lookup('ip', IP)
            self.assertEqual(cached['lookup_source'], 'cache')
            self.assertEqual(self.transport.call_count, 1)

    def test_virustotal_get_uses_hash_and_preserves_engine_counts(self):
        self.transport.side_effect = None
        self.transport.return_value = response({'data': {'attributes': {'sha256': HASH,
            'last_analysis_date': self.now,
            'last_analysis_stats': {'malicious': 2, 'suspicious': 1, 'harmless': 5, 'undetected': 40}}}})
        result = self.engine.lookup('hash', HASH.upper())
        self.transport.assert_called_once_with('www.virustotal.com', f'/api/v3/files/{HASH}',
                                               {'x-apikey': 'UNIT_TEST'}, 8)
        self.assertEqual(result['result']['last_analysis_stats']['malicious'], 2)

    def test_virustotal_404_is_negative_cache_and_expires(self):
        self.transport.side_effect = None
        self.transport.return_value = (404, None, b'')
        self.assertEqual(self.engine.lookup('hash', HASH)['status'], 'not_found')
        self.assertEqual(self.engine.lookup('hash', HASH)['lookup_source'], 'cache')
        self.now += 21601
        self.assertEqual(self.engine.lookup('hash', HASH)['lookup_source'], 'api')
        self.assertEqual(self.transport.call_count, 2)

    def test_provider_cooldown_and_batch_budget_are_separate(self):
        self.transport.side_effect = None
        self.transport.return_value = (429, '120', b'')
        first = self.engine.lookup('ip', IP)
        self.assertEqual(first['retry_after_unix'], self.now + 120)
        next_run = Lookup(self.db, KEYS, max_queries=1, transport=self.transport, now=lambda: self.now)
        self.assertEqual(next_run.lookup('ip', IP)['status'], 'provider_cooldown')
        self.transport.return_value = (404, None, b'')
        self.assertEqual(next_run.lookup('hash', HASH)['status'], 'not_found')
        self.assertEqual(next_run.lookup('hash', 'b'*64)['status'], 'budget_exhausted')
        self.assertEqual(self.transport.call_count, 2)

    def test_timeout_and_auth_errors_are_not_cached(self):
        self.transport.side_effect = [TimeoutError(), (401, None, b''), (200, None, b'{bad-json}')]
        self.assertEqual(self.engine.lookup('ip', IP)['status'], 'timeout')
        self.assertEqual(self.engine.lookup('ip', IP)['status'], 'auth_error')
        self.assertEqual(self.engine.lookup('ip', IP)['status'], 'invalid_response')

    def test_offline_and_missing_key_never_reach_transport(self):
        self.assertEqual(Lookup(transport=self.transport).lookup('ip', IP)['status'], 'offline')
        missing = Lookup(self.db, transport=self.transport)
        self.assertEqual(missing.lookup('hash', HASH)['status'], 'missing_key')
        self.transport.assert_not_called()

    def test_wazuh_fim_field_and_partial_snapshot(self):
        hit = {'_id': 'DOC', '_index': 'test', '_source': {'id': 'EVENT', 'rule': {'id': '550'},
                'data': {'src_ip': IP}, 'syscheck': {'sha256_after': HASH, 'md5_after': 'b'*32}}}
        snapshot = {'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [hit]}}
        [row] = alerts(snapshot)
        self.assertEqual((row['ip'], row['hash']), (IP, HASH))
        snapshot['hits']['total']['value'] = 2
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            list(alerts(snapshot))

    def test_actual_ssh_and_eve_alerts_preserve_ids_without_requests(self):
        paths = [ROOT/'evidence/detection'/name for name in ('ssh-sequence-live.json', 'suricata-live.json')]
        report = list(enrich([*paths, paths[-1]], self.engine))
        self.assertEqual(len(report), 10)
        results = {row['alert_id']: row['lookups'][0]['status'] for row in report}
        self.assertEqual(results['1794299394.82178'], 'skipped_non_public')
        self.assertEqual(results['1794300261.255564'], 'skipped_non_public')
        self.assertEqual(results['1794300261.258098'], 'no_indicator')
        self.transport.assert_not_called()

    def test_actual_fim_deletion_repeats_hash_but_is_cleanup_only(self):
        path = ROOT/'evidence/detection/threat-intel-fim.json'
        sample = json.loads(path.read_bytes())
        added, deleted = list(enrich([path], Lookup(transport=self.transport)))
        self.assertEqual((added['rule_id'], deleted['rule_id']), ('554', '553'))
        self.assertEqual(added['lookups'][0]['indicator'], sample['local_sha256'])
        self.assertEqual(added['lookups'][0]['status'], 'offline')
        self.assertEqual(deleted['lookups'], [{'status': 'no_indicator'}])
        self.transport.assert_not_called()


if __name__ == '__main__':
    unittest.main()
