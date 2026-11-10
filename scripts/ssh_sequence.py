"""Correlate SSH authentication events in an exported lab snapshot (offline)."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path


def correlate(events, failures=3, seconds=60):
    if failures < 1 or seconds < 1:
        raise ValueError('Threshold and window must be positive')
    window = timedelta(seconds=seconds)
    pending = defaultdict(deque)
    seen = set()
    matches = []
    ordered = []
    for event in events:
        stamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('Timestamp lacks timezone')
        ordered.append((stamp, event))
    # At equal timestamps, do not treat a failure as having preceded a success.
    ordered.sort(key=lambda item: (item[0], item[1]['outcome'] != 'success'))
    for stamp, event in ordered:
        key = (event['host'], event['source_ip'], event['account'])
        if not all(key) or not event['connection']:
            raise ValueError('Missing SSH correlation field')
        outcome = event['outcome']
        if outcome not in ('failure', 'success'):
            raise ValueError('Unknown SSH outcome')
        identity = (*key, event['connection'], outcome)
        if identity in seen:
            continue
        seen.add(identity)
        recent = pending[key]
        while recent and stamp - recent[0][0] > window:
            recent.popleft()
        if outcome == 'failure':
            recent.append((stamp, event))
            continue
        if len(recent) >= failures:
            matches.append({
                'host': key[0], 'source_ip': key[1], 'account': key[2],
                'failure_count': len(recent),
                'first_failure': recent[0][1]['timestamp'],
                'success': event['timestamp'],
                'failure_documents': [row['archive'] for _, row in recent],
                'success_document': event['archive'],
                'success_alerts': event['alerts'],
            })
        # A subsequent successful login must have a new preceding burst.
        recent.clear()
    return matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--failures', type=int, default=3)
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()
    snapshot = json.loads(args.input.read_bytes())
    matches = correlate(snapshot['events'], args.failures, args.seconds)
    print(json.dumps({'run_id': snapshot['run_id'], 'matches': matches}, indent=2))


if __name__ == '__main__':
    main()
