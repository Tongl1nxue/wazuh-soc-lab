"""Bounded SSH/Web detection lab on soc-ubuntu only; no third-party traffic.

Requires phase1-log-pipeline.py alongside this script on the guest.
audit -> configure (backup + actual baseline requests + replay tests + rule)
-> verify (live tuned-rule requests and six invalid-user SSH connections).
"""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

spec=importlib.util.spec_from_file_location('pipeline',Path(__file__).with_name('phase1-log-pipeline.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
D=p.ROOT/'detection-lab'
RULE_ID='100110'
TARGET='/var/ossec/etc/rules/soc_web_rules.xml'


def write(path,obj):
    p.save_json(path,obj)


def rule(broad=False):
    pattern=r'\.env' if broad else r'^/\.env(?:\?.*)?$'
    return f'''<group name="web,accesslog,soc_lab,">
  <rule id="{RULE_ID}" level="7">
    <if_sid>31101</if_sid>
    <id>^404$</id>
    <url type="pcre2">{pattern}</url>
    <description>Denied request for environment configuration path (lab).</description>
    <group>soc_sensitive_path,</group>
  </rule>
</group>
'''


def deploy(text):
    source=D/'soc_web_rules.xml';source.write_text(text);source.chmod(0o644)
    p.cmd(p.COMPOSE+['cp',str(source),'wazuh.manager:'+TARGET])
    p.container('wazuh.manager',['/var/ossec/bin/wazuh-analysisd','-t'])


def logtest(log):
    result=subprocess.run(p.COMPOSE+['exec','-T','wazuh.manager','/var/ossec/bin/wazuh-logtest'],
        input=log+'\n',capture_output=True,text=True,cwd=p.STACK,timeout=30)
    ids=re.findall(r"id: '([0-9]+)'",result.stdout+'\n'+result.stderr)
    return {'exit':result.returncode,'rule_id':ids[-1] if ids else None,
            'output':result.stdout,'stderr':result.stderr}


def request(path,token):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url='http://127.0.0.1:8080'+path+'?soc_run='+token
    try:
        with opener.open(url,timeout=5) as response: status=response.status
    except urllib.error.HTTPError as error:status=error.code
    return {'path':path,'status':status,'url':url}


def search(token,index='wazuh-archives-*',location='/var/log/nginx/soc_access.log'):
    return p.query(index,{'size':100,'query':{'bool':{'filter':[
        {'term':{'agent.name':'soc-ubuntu'}},{'term':{'location':location}},
        {'match_phrase':{'full_log':token}}]}},'sort':[{'timestamp':'asc'}]})


def wait_hits(token,minimum,index='wazuh-archives-*',location='/var/log/nginx/soc_access.log'):
    last=None
    for _ in range(35):
        last=search(token,index,location)
        if len(last['hits']['hits'])>=minimum:return last
        time.sleep(2)
    return last


def main():
    if p.cmd(['hostname']).stdout.strip()!='soc-ubuntu':raise SystemExit('Wrong guest')
    D.mkdir(mode=0o700,exist_ok=True)
    mode=sys.argv[1]
    if mode=='audit':
        mem=Path('/proc/meminfo').read_text()
        config=p.container('wazuh.manager',['cat','/var/ossec/etc/ossec.conf']).stdout
        clean=re.sub(r'<!--.*?-->','',config,flags=re.S)
        responses=re.findall(r'<active-response>(.*?)</active-response>',clean,re.S)
        active=[s for s in responses if '<command>' in s and '<disabled>yes</disabled>' not in s]
        collision=p.container('wazuh.manager',['grep','-R','-l','id="'+RULE_ID+'"','/var/ossec/etc/rules','/var/ossec/ruleset/rules'],False)
        summary={'time':dt.datetime.now().astimezone().isoformat(),
          'available_memory_mib':int(re.search(r'MemAvailable:\s+(\d+)',mem).group(1))//1024,
          'free_disk_gib':round(shutil.disk_usage('/').free/2**30,1),
          'active_response_bindings':len(active),'rule_id_collision':collision.returncode==0,
          'nginx_config_test':p.cmd(['nginx','-t'],False).returncode==0,
          'containers':p.cmd(p.COMPOSE+['ps','--format','{{.Service}} {{.State}}']).stdout.strip()}
        write(D/'audit.json',summary);print(json.dumps(summary,indent=2))
    elif mode=='configure':
        audit=json.loads((D/'audit.json').read_text())
        if audit['active_response_bindings'] or audit['rule_id_collision']:
            raise SystemExit('Inspect active responses / rule ID collision before testing')
        if audit['available_memory_mib']<1500 or audit['free_disk_gib']<8:raise SystemExit('Insufficient resources')
        backup=D/'backup'
        if backup.exists() and (backup/'compose.lab.yml').exists():
            raise SystemExit('Persistent configuration already applied; refusing to overwrite backup')
        if not backup.exists():
            backup.mkdir(mode=0o700)
            # Full existing user rule directory is backed up without exposing it.
            p.cmd(p.COMPOSE+['cp','wazuh.manager:/var/ossec/etc/rules',str(backup/'rules')])
            for name in ['sshd','nginx']:
                if name=='sshd':text=p.cmd(['sshd','-T']).stdout
                else:text=Path('/etc/nginx/sites-available/soc-lab').read_text()
                (backup/(name+'.txt')).write_text(text)
        paths=['/index.html','/ordinary-missing-page','/docs/.env-guide','/.env','/.env.example']
        if (D/'baseline.json').exists():
            baseline=json.loads((D/'baseline.json').read_text())
            hits=baseline['archive_result']
        else:
            token='soc-baseline-'+uuid.uuid4().hex[:12]
            requests=[request(path,token) for path in paths]
            hits=wait_hits(token,len(paths))
            write(D/'baseline.json',{'token':token,'requests':requests,'archive_result':hits})
        events={h['_source']['data']['url'].split('?')[0]:h['_source']['full_log'] for h in hits['hits']['hits']}
        if not all(path in events for path in paths):raise SystemExit('Baseline archive collection incomplete')
        tests={}
        try:
            for label,broad in [('broad_candidate',True),('tuned',False)]:
                deploy(rule(broad))
                tests[label]={path:logtest(events[path]) for path in paths}
            expected={'/index.html':False,'/ordinary-missing-page':False,
                      '/docs/.env-guide':False,'/.env':True,'/.env.example':False}
            passed=all((tests['tuned'][path]['rule_id']==RULE_ID)==match for path,match in expected.items())
            write(D/'logtest.json',tests)
            if not passed:raise RuntimeError('Tuned rule replay failed; restoring rule directory state')
        except Exception:
            p.container('wazuh.manager',['rm','-f',TARGET])
            raise
        # Persist both the named volume and a read-only source mount for rebuilds.
        import yaml
        compose_path=p.STACK/'compose.lab.yml'
        shutil.copy2(compose_path,backup/'compose.lab.yml')
        configdir=p.STACK/'config/soc_lab';configdir.mkdir(mode=0o755,exist_ok=True)
        source=configdir/'soc_web_rules.xml';source.write_text(rule());source.chmod(0o644)
        compose=yaml.safe_load(compose_path.read_text())
        mount='./config/soc_lab/soc_web_rules.xml:'+TARGET+':ro'
        compose['services']['wazuh.manager']['volumes'].append(mount)
        compose_path.write_text(yaml.safe_dump(compose,sort_keys=False))
        p.cmd(p.COMPOSE+['config','--quiet'])
        p.cmd(p.COMPOSE+['up','-d','--no-deps','wazuh.manager'])
        write(D/'configuration.json',{'rule_id':RULE_ID,'replay_passed':passed,
             'broad_false_positive':tests['broad_candidate']['/docs/.env-guide']['rule_id']==RULE_ID})
        print(json.dumps(json.loads((D/'configuration.json').read_text()),indent=2))
    elif mode=='verify':
        token='soc-detect-'+uuid.uuid4().hex[:12]
        paths=['/index.html','/ordinary-missing-page','/docs/.env-guide','/.env','/.env.example']
        requests=[request(path,token) for path in paths]
        # Nonexistent account; no password guessing, account creation or credential changes.
        username='socinvalid'+uuid.uuid4().hex[:10]
        if p.cmd(['getent','passwd',username],False).returncode==0:raise SystemExit('Username unexpectedly exists')
        ssh=[]
        for _ in range(6):
            response=p.cmd(['ssh','-F','/dev/null','-i','/dev/null','-o','IdentitiesOnly=yes',
              '-o','BatchMode=yes','-o','PreferredAuthentications=publickey',
              '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(D/'known_hosts'),
              '-o','ConnectTimeout=3',username+'@127.0.0.1','true'],False)
            ssh.append({'exit':response.returncode,'stderr':response.stderr})
            time.sleep(1)
        web=wait_hits(token,5)
        web_alert=wait_hits(token,1,'wazuh-alerts-*')
        ssh_events=wait_hits(username,6,'wazuh-archives-*','/var/log/auth.log')
        ssh_alerts=wait_hits(username,1,'wazuh-alerts-*','/var/log/auth.log')
        data={'run_id':token,'ssh_test_user':username,'requests':requests,'ssh_attempts':ssh,
              'web_archives':web,'web_alerts':web_alert,'ssh_archives':ssh_events,'ssh_alerts':ssh_alerts}
        write(D/(token+'.json'),data)
        wh=[h['_source'] for h in web_alert['hits']['hits']]
        sh=[h['_source'] for h in ssh_alerts['hits']['hits']]
        custom=[e for e in wh if e.get('rule',{}).get('id')==RULE_ID]
        web_all=[h['_source'] for h in web['hits']['hits']]
        probe=[e for e in web_all if e.get('data',{}).get('url','').split('?')[0]=='/.env']
        negatives=[e for e in web_all if e.get('data',{}).get('url','').split('?')[0]!='/.env']
        summary={'run_id':token,'requested_paths':requests,'ssh_connections':len(ssh),
          'ssh_nonzero_exits':sum(bool(r['exit']) for r in ssh),
          'web_archive_count':len(web_all),'custom_alert_count':len(custom),
          'custom_alert_ids':[e['id'] for e in custom],
          'ssh_rule_ids':sorted({e['rule']['id'] for e in sh}),
          'ssh_alert_ids':[e['id'] for e in sh],
          'negative_custom_matches':sum(e.get('rule',{}).get('id')==RULE_ID for e in negatives),
          'passed':bool(custom) and bool(sh) and len(web_all)>=5 and bool(probe)
             and not any(e.get('rule',{}).get('id')==RULE_ID for e in negatives)}
        write(D/'summary.json',summary);print(json.dumps(summary,indent=2))
        if not summary['passed']:raise SystemExit(1)
    elif mode=='reconcile':
        summary=json.loads((D/'summary.json').read_text());token=summary['run_id']
        raw_path=D/(token+'.json');raw=json.loads(raw_path.read_text())
        original=D/(token+'-initial.json')
        if not original.exists():shutil.copy2(raw_path,original)
        raw['ssh_archives']=search(raw['ssh_test_user'],'wazuh-archives-*','/var/log/auth.log')
        raw['ssh_alerts']=search(raw['ssh_test_user'],'wazuh-alerts-*','/var/log/auth.log')
        sh=[h['_source'] for h in raw['ssh_alerts']['hits']['hits']]
        summary['ssh_alert_ids']=[e['id'] for e in sh]
        summary['ssh_rule_ids']=sorted({e['rule']['id'] for e in sh})
        summary['ssh_invalid_user_log_entries']=sum('Invalid user ' in h['_source'].get('full_log','')
            for h in raw['ssh_archives']['hits']['hits'])
        summary['reconciled_at']=dt.datetime.now().astimezone().isoformat()
        summary['free_disk_gib']=round(shutil.disk_usage('/').free/2**30,1)
        summary['filebeat_version']=p.container('wazuh.manager',['filebeat','version']).stdout.strip()
        write(raw_path,raw);write(D/'summary.json',summary)
        print(json.dumps(summary,indent=2))
    elif mode=='diagnose':
        live=p.container('wazuh.manager',['cat','/var/ossec/etc/ossec.conf']).stdout
        fb=p.container('wazuh.manager',['cat','/etc/filebeat/filebeat.yml']).stdout
        match=re.search(r'archives:\s*\n\s*enabled:\s*(\w+)',fb)
        print(json.dumps({'live_logall_json':re.findall(r'<logall_json>(.*?)</logall_json>',live),
           'filebeat_archives_enabled':match.group(1) if match else None}))
        mounts=json.loads(p.cmd(['docker','inspect','single-node-wazuh.manager-1','--format','{{json .Mounts}}']).stdout)
        print(json.dumps({'filebeat_mounts':[{k:m[k] for k in ['Type','Destination']} for m in mounts if 'filebeat' in m['Destination']]}))
        init=p.container('wazuh.manager',['sh','-c',
             'grep -R -n -E "filebeat.*yml|configure_filebeat" /etc/cont-init.d /entrypoint.sh /etc/services.d 2>/dev/null'],False)
        print(json.dumps({'archive_initialization_lines':init.stdout}))
        tests=json.loads((D/'logtest.json').read_text())
        summary={label:{path:{'rule_id':r['rule_id'],'exit':r['exit'],
                 'rule_lines':[line for line in (r['output']+'\n'+r['stderr']).splitlines()
                   if any(key in line for key in ['id:','name:','ERROR','WARNING','description:'])]}
                   for path,r in cases.items()} for label,cases in tests.items()}
        print(json.dumps(summary,indent=2))
    elif mode=='restore':
        backup=D/'backup'
        import yaml
        config=yaml.safe_load((backup/'compose.lab.yml').read_text())
        # Roll back this rule while preserving the separately verified archives fix.
        if (backup/'compose.before-archives.yml').exists():
            config['services']['wazuh.manager']['volumes'].append('./config/soc_lab/filebeat-run:/etc/services.d/filebeat/run:ro')
        (p.STACK/'compose.lab.yml').write_text(yaml.safe_dump(config,sort_keys=False))
        p.cmd(p.COMPOSE+['up','-d','--no-deps','wazuh.manager'])
        # Only the rule created by this experiment is removed; prior files stay intact.
        p.container('wazuh.manager',['rm','-f',TARGET])
        p.cmd(p.COMPOSE+['restart','wazuh.manager'])
        print('Detection rule rolled back; separate archives persistence fix and evidence retained.')


if __name__=='__main__':main()
