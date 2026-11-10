"""Export the minimal fields needed to reproduce this lab batch's statistics."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('analysis', Path(__file__).with_name('analyze-alerts.py'))
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = json.loads(args.input.read_bytes())
    public = {'run_id': original['run_id']}
    for names in analysis.STREAMS.values():
        for name in names:
            response = original[name]
            hits = []
            for hit in response['hits']['hits']:
                event = hit['_source']
                minimal = {key: event[key] for key in ('id', 'timestamp', 'location')}
                if event.get('rule'):
                    minimal['rule'] = {key: event['rule'][key] for key in ('id', 'level')}
                if name.startswith('web_'):
                    minimal['data'] = {'id': event['data']['id'], 'url': analysis.public_url(event['data']['url'])}
                hits.append({'_index': hit['_index'], '_id': hit['_id'], '_source': minimal})
            public[name] = {
                'timed_out': response['timed_out'],
                '_shards': {'failed': response['_shards']['failed']},
                'hits': {'total': response['hits']['total'], 'hits': hits},
            }
    expected, _, _ = analysis.analyze(original)
    actual, _, _ = analysis.analyze(public)
    if actual != expected:
        raise SystemExit('Public export changed an analysis result')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(public, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Public snapshot verified: {len(actual["archive"])} archives, {len(actual["alert"])} alerts.')


if __name__ == '__main__':
    main()
