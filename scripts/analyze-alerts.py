"""Classify an actual detection-lab snapshot and export sanitized UTF-8 CSV.

This is a bounded experiment report, not all SIEM activity. No network calls.
"""
import argparse
from collections import Counter
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

STREAMS={'archive':['web_archives','ssh_archives'], 'alert':['web_alerts','ssh_alerts']}
LABELS={'100110':'Web敏感路径请求','31101':'Web普通4xx告警','5710':'SSH无效用户连接'}
FIELDS=['record_type','category','timestamp_utc','timestamp_china','agent_alias',
        'index','document_id','event_id','rule_id','rule_level','http_status','url_path','log_source']


def unique_hits(hits):
    """Use index+document ID: archive source event IDs are not always unique."""
    seen=set();out=[]
    for hit in hits:
        key=(hit['_index'],hit['_id'])
        if key not in seen:
            seen.add(key);out.append(hit)
    return out


def csv_cell(value):
    text='' if value is None else str(value)
    # Do not allow imported event strings to become executable spreadsheet formulas.
    return "'"+text if text.lstrip().startswith(('=','+','-','@')) else text


def export_csv(path,fields,rows):
    with path.open('w',newline='',encoding='utf-8-sig') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields)
        writer.writeheader()
        writer.writerows({k:csv_cell(row.get(k)) for k in fields} for row in rows)


def normalize(hit,kind):
    source=hit['_source'];rule=source.get('rule',{});data=source.get('data',{})
    timestamp=dt.datetime.fromisoformat(source['timestamp'].replace('Z','+00:00'))
    if timestamp.tzinfo is None:raise ValueError('Source timestamp lacks timezone')
    rid=str(rule.get('id',''))
    web=source.get('location')=='/var/log/nginx/soc_access.log'
    category=LABELS.get(rid,'Web访问日志' if web else 'SSH其他日志')
    return {'record_type':kind,'category':category,
       'timestamp_utc':timestamp.astimezone(dt.timezone.utc).isoformat(),
       'timestamp_china':timestamp.astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat(),
       'agent_alias':'LAB-UBUNTU','index':hit['_index'],'document_id':hit['_id'],
       'event_id':str(source.get('id','')),'rule_id':rid,'rule_level':rule.get('level',''),
       'http_status':data.get('id','') if web else '',
       'url_path':public_url(data.get('url','')) if web else '',
       'log_source':source.get('location','')}


def public_url(value):
    parts=urlsplit(value)
    markers=[(key,val) for key,val in parse_qsl(parts.query)
             if key=='soc_run' and re.fullmatch(r'soc-detect-[a-f0-9]{12}',val)]
    return parts.path+('?' + urlencode(markers) if markers else '')


def analyze(snapshot):
    records={};completeness={}
    for kind,streams in STREAMS.items():
        hits=[]
        for name in streams:
            response=snapshot[name]
            if response.get('timed_out') or response.get('_shards',{}).get('failed',0):
                raise ValueError('Timed out or failed shards: '+name)
            page=response['hits'];total=page['total']
            if total['relation']!='eq' or total['value']!=len(page['hits']):
                raise ValueError('Incomplete query snapshot: '+name+'; paginate/recollect first')
            completeness[name]={'returned':len(page['hits']),'total':total['value']}
            hits.extend(page['hits'])
        records[kind]=sorted((normalize(h,kind) for h in unique_hits(hits)),
                            key=lambda row:(row['timestamp_utc'],row['document_id']))
    counts=Counter((row['category'],row['rule_id'],str(row['rule_level'])) for row in records['alert'])
    totals=[{'category':key[0],'rule_id':key[1],'rule_level':key[2],'alert_count':count}
            for key,count in sorted(counts.items())]
    manifest={'run_id':snapshot['run_id'],'scope':'single_authorized_lab_snapshot',
       'archive_records':len(records['archive']),'alert_records':len(records['alert']),
       'alert_counts_by_rule':dict(Counter(row['rule_id'] for row in records['alert'])),
       'query_completeness':completeness,
       'counting_note':'Archives and alerts are counted separately; alert rows are not incident counts.',
       'redaction':'Original usernames, addresses, raw logs and secrets are excluded; host uses an alias.'}
    return records,totals,manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    raw=args.input.read_bytes();snapshot=json.loads(raw)
    records,totals,manifest=analyze(snapshot)
    args.output.mkdir(parents=True,exist_ok=True)
    export_csv(args.output/'alerts.csv',FIELDS,records['alert'])
    export_csv(args.output/'archives.csv',FIELDS,records['archive'])
    export_csv(args.output/'alert-statistics.csv',['category','rule_id','rule_level','alert_count'],totals)
    manifest['source_sha256']=hashlib.sha256(raw).hexdigest()
    (args.output/'analysis-summary.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:manifest[k] for k in ['run_id','archive_records','alert_records','alert_counts_by_rule']},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
