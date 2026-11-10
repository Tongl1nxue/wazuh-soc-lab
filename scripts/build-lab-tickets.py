"""Build two explicitly simulated tickets from verified lab evidence.

Default: draft for review. --close-lab records the project author's explicit
confirmation that the documented authorized-lab findings have been reviewed.
No incident response, network access, blocking or password change is performed.
"""
import argparse
import csv
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('analysis',Path(__file__).with_name('analyze-alerts.py'))
analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--close-lab',action='store_true')
    args=parser.parse_args()
    operations=ROOT/'output/operations'
    stats=json.loads((operations/'analysis-summary.json').read_text(encoding='utf-8'))
    verified=json.loads((ROOT/'evidence/detection/verification.json').read_text())
    snapshot=ROOT/'local-evidence/detection-lab'/f"{verified['run_id']}.json"
    actual_hash=hashlib.sha256(snapshot.read_bytes()).hexdigest()
    if actual_hash!=stats['source_sha256'] or stats['run_id']!=verified['run_id']:
        raise SystemExit('Evidence changed; regenerate and review statistics before making tickets')
    if not verified['passed'] or verified['negative_custom_matches']!=0:
        raise SystemExit('Detection verification has not passed')
    # Recalculate from the actual source; CSV edits cannot silently alter tickets.
    rows,_,fresh=analysis.analyze(json.loads(snapshot.read_bytes()))
    if fresh['alert_counts_by_rule']!=stats['alert_counts_by_rule']:
        raise SystemExit('Statistics differ from source evidence')
    alerts=rows['alert']
    ssh=[r for r in alerts if r['rule_id']=='5710']
    web=[r for r in alerts if r['rule_id']=='100110']
    if set(r['event_id'] for r in ssh)!=set(verified['ssh_alert_ids']):
        raise SystemExit('SSH alert IDs do not reconcile')
    if set(r['event_id'] for r in web)!=set(verified['custom_alert_ids']):
        raise SystemExit('Web alert IDs do not reconcile')
    out=ROOT/'output/tickets';out.mkdir(parents=True,exist_ok=True)
    now=dt.datetime.now(dt.timezone.utc).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec='seconds')
    previous={}
    if (out/'tickets.json').exists():
        previous={t['ticket_id']:t for t in json.loads((out/'tickets.json').read_text(encoding='utf-8'))}
    definitions=[
      ('SSH','SSH 无效用户名连接',ssh,
       '实验脚本对本机回环 SSH 发起 6 次不存在用户名连接，未进行密码猜测。',
       '授权模拟活动；无效用户连接检测符合预期。不能据此认定口令爆破成功。',
       '关联 auth.log 与规则 5710；核对本次测试背景并保留证据。未封禁 IP、未修改账户或密码。',
       f"最终复测客户端 {verified['ssh_connections']} 次连接均非零退出；归档有 {verified['ssh_invalid_user_log_entries']} 条 Invalid user，规则 5710 告警 {len(ssh)} 条。",
       '实际连接为 6 次，SSH archives 为 12 条，日志条数不能充当连接次数。'),
      ('WEB','Web 环境配置路径访问',web,
       '实验脚本请求自有 Nginx 的 /.env，返回 HTTP 404，命中自定义规则 100110。',
       '授权敏感路径访问模拟；没有文件成功返回的证据。404 不代表 IPS 阻断。',
       '复核 URL、状态和原始日志；用真实日志正反例收紧规则边界，修复归档转发持久化并复测。未新增拦截策略。',
       f"最终批次 {verified['web_archive_count']} 条 Web archives；自定义告警 {len(web)} 条；四个负例的自定义命中为 0。",
       '普通 404 仍可产生原生 31101 告警；该规则不覆盖所有敏感文件、编码变体或 HTTP 200 暴露。')]
    tickets=[]
    for kind,title,linked,discovery,verdict,action,retest,limit in definitions:
        if not linked:raise SystemExit('Missing primary alert for '+kind)
        first=min(r['timestamp_china'] for r in linked)
        last=max(r['timestamp_china'] for r in linked)
        ticket_id='LAB-'+first[:10].replace('-','')+'-'+kind+'-001'
        old=previous.get(ticket_id)
        if old and old['status']=='已关闭（模拟工单）' and old['evidence_sha256']!=actual_hash:
            raise SystemExit('Closed ticket evidence changed; preserve it and create a new case')
        confirmed=args.close_lab or bool(old and old['status']=='已关闭（模拟工单）')
        ticket={'ticket_id':ticket_id,'title':title,'record_type':'模拟工单，来源为真实授权实验',
          'run_id':verified['run_id'],'agent_alias':'LAB-UBUNTU',
          'first_alert_time_china':first,'last_alert_time_china':last,
          'rule_ids':sorted({r['rule_id'] for r in linked}),
          'rule_levels':sorted({int(r['rule_level']) for r in linked}),
          'primary_alert_ids':[r['event_id'] for r in linked],
          'primary_document_ids':[r['document_id'] for r in linked],
          'discovery':discovery,'analysis':verdict,'executed_actions':action,
          'retest':retest,'limitations':limit,'evidence_sha256':actual_hash,
          'drafted_at':old['drafted_at'] if old else now,
          'status':'已关闭（模拟工单）' if confirmed else '技术复测完成，待关闭复核',
          'closed_at':old.get('closed_at') if old and old.get('closed_at') else now if confirmed else None,
          'closure_basis':'项目作者执行 --close-lab 确认已复核授权实验记录' if confirmed else '尚未执行关闭确认',
          'production_response_executed':False}
        tickets.append(ticket)
        ids='\n'.join('- `'+value+'`' for value in ticket['primary_alert_ids'])
        text=f'''# {ticket_id}：{title}

**模拟工单；关联证据来自真实本地授权实验。**

| 字段 | 内容 |
| --- | --- |
| 状态 | {ticket['status']} |
| 主机 | LAB-UBUNTU |
| 批次 | {ticket['run_id']} |
| 首条关联告警时间（北京时间） | {first} |
| 末条关联告警时间（北京时间） | {last} |
| 规则 | {', '.join(ticket['rule_ids'])} |
| 规则级别 | {', '.join(str(x) for x in ticket['rule_levels'])} |
| 工单整理时间 | {ticket['drafted_at']} |
| 关闭时间 | {ticket['closed_at'] or '尚未关闭'} |

## 发现与研判

{discovery}

{verdict}

## 已执行操作

{action}

## 复测与关闭依据

{retest}

{ticket['closure_basis']}。关闭仅表示本次授权模拟记录处理完成，不代表生产攻击处置或修复。

## 关联原始告警编号

{ids}

索引文档 ID：{', '.join(ticket['primary_document_ids'])}。

来源：项目 evidence/detection/events.json、verification.json 与 output/operations/analysis-summary.json。源快照 SHA-256：`{actual_hash}`。原始日志仍保留在本地私有证据目录。

## 范围限制

{limit}
'''
        (out/(ticket_id+'.md')).write_text(text,encoding='utf-8')
    (out/'tickets.json').write_text(json.dumps(tickets,ensure_ascii=False,indent=2),encoding='utf-8')
    fields=['ticket_id','title','record_type','status','agent_alias','first_alert_time_china',
            'last_alert_time_china','rule_ids','rule_levels','primary_alert_ids','discovery',
            'analysis','executed_actions','retest','limitations','closed_at','closure_basis','evidence_sha256']
    csv_rows=[]
    for ticket in tickets:
        row=dict(ticket)
        for key in ['rule_ids','rule_levels','primary_alert_ids']:row[key]='; '.join(map(str,row[key]))
        csv_rows.append(row)
    analysis.export_csv(out/'tickets.csv',fields,csv_rows)
    print(json.dumps({'simulated_tickets':len(tickets),
       'statuses':{t['ticket_id']:t['status'] for t in tickets},
       'primary_alert_links':sum(len(t['primary_alert_ids']) for t in tickets)},ensure_ascii=True,indent=2))


if __name__=='__main__':main()
