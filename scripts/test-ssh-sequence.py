"""Synthetic unit tests. The indexed live snapshot is verified separately."""
from datetime import datetime, timedelta, timezone
import unittest

from ssh_sequence import correlate


def event(second, connection, outcome='failure', account='A', host='lab', source='127.0.0.1'):
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)
    return {'timestamp': timestamp.isoformat(), 'connection': connection, 'outcome': outcome,
            'account': account, 'host': host, 'source_ip': source,
            'archive': {'index': 'synthetic', 'document_id': connection}, 'alerts': []}


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.failures = [event(n, f'failure-{n}') for n in range(3)]

    def test_sorts_and_matches_inclusive_window(self):
        success = event(60, 'success', 'success')
        matches = correlate([success, *reversed(self.failures)])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['failure_count'], 3)
        self.assertEqual(matches[0]['success_document'], success['archive'])

    def test_expired_window(self):
        self.assertEqual(correlate([*self.failures, event(61, 'success', 'success')]), [])

    def test_dedup_connection_even_across_distinct_archive_documents(self):
        duplicate = {**self.failures[0], 'archive': {'index': 'synthetic', 'document_id': 'duplicate'}}
        events = [*self.failures[:2], duplicate, event(3, 'success', 'success')]
        self.assertEqual(correlate(events), [])

    def test_other_account_host_and_source_do_not_match(self):
        for change in ({'account': 'B'}, {'host': 'other'}, {'source': '127.0.0.2'}):
            with self.subTest(change=change):
                self.assertEqual(correlate([*self.failures, event(3, 'success', 'success', **change)]), [])

    def test_repeated_success_does_not_reuse_failures(self):
        self.assertEqual(len(correlate([*self.failures, event(3, 's1', 'success'), event(4, 's2', 'success')])), 1)

    def test_failure_at_success_timestamp_is_not_earlier(self):
        self.assertEqual(correlate([*self.failures, event(2, 'success', 'success')]), [])


if __name__ == '__main__':
    unittest.main()
