"""Run only on the existing SOC guest as root. No external network requests.

audit: read-only inventory. configure: back up and enable JSON archives+shipping.
verify: issue ONE real local Nginx request and query archive/SSH events.
restore: restore the backed-up manager/Filebeat config (preserves evidence).
"""
import base64
import datetime as dt
import hashlib
import http.client
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

ROOT=Path('/opt/soc-lab')
STACK=ROOT/'wazuh-docker/single-node'
OUT=ROOT/'phase1-pipeline'
BACKUP=OUT/'backup'
COMPOSE=['docker','compose','-f',str(STACK/'compose.lab.yml')]


def cmd(args, check=True):
    return subprocess.run(args,cwd=STACK,capture_output=True,text=True,check=check)


def container(service,args,check=True):
    return cmd(COMPOSE+['exec','-T',service]+args,check)


def save_json(path,obj):
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False))
    path.chmod(0o600)


def query(index,body):
    creds=json.loads((ROOT/'credentials.json').read_text())
    context=ssl.create_default_context(cafile=str(STACK/'config/wazuh_indexer_ssl_certs/root-ca.pem'))
    # cloud-init may regenerate /etc/hosts on reboot. Connect to the existing
    # loopback binding while checking both the signing CA and the exact DNS SAN.
    context.check_hostname=False
    conn=http.client.HTTPSConnection('127.0.0.1',9200,context=context,timeout=15)
    try:
        conn.connect()
        if ('DNS','wazuh.indexer') not in conn.sock.getpeercert().get('subjectAltName',()):
            raise ssl.CertificateError('Unexpected indexer certificate identity')
        conn.request('POST','/'+index+'/_search',body=json.dumps(body).encode(),
            headers={'Content-Type':'application/json',
             'Authorization':'Basic '+base64.b64encode(('admin:'+creds['admin']).encode()).decode()})
        response=conn.getresponse()
        data=json.load(response)
        if response.status!=200:
            raise RuntimeError('Indexer HTTP '+str(response.status))
        return data
    finally:
        conn.close()


def main():
    if cmd(['hostname']).stdout.strip()!='soc-ubuntu':
        raise SystemExit('This script is restricted to the existing soc-ubuntu guest')
    OUT.mkdir(mode=0o700,exist_ok=True)
    mode=sys.argv[1]
    manager=STACK/'config/wazuh_cluster/wazuh_manager.conf'
    if mode=='audit':
        import yaml
        services=yaml.safe_load((STACK/'compose.lab.yml').read_text())['services']
        data={'time':dt.datetime.now().astimezone().isoformat(),
            'images':{k:v['image'] for k,v in services.items()},
            'guest_memory':cmd(['free','-h']).stdout.strip(),
            'guest_disk':cmd(['df','-h','/']).stdout.strip(),
            'agent_version':cmd(['dpkg-query','-W','-f=${Version}','wazuh-agent']).stdout,
            'container_states':cmd(COMPOSE+['ps','--format','{{.Service}} {{.State}}']).stdout.strip(),
            'services':cmd(['systemctl','is-active','wazuh-agent','nginx','docker'],False).stdout.strip(),
            'agent_log_sources':re.findall(r'<location>(.*?)</location>',Path('/var/ossec/etc/ossec.conf').read_text()),
            'manager_archive_json':re.findall(r'<logall_json>(.*?)</logall_json>',manager.read_text()),
            'filebeat_archives_config':container('wazuh.manager',['cat','/etc/filebeat/filebeat.yml']).stdout,
            'custom_rule_names':container('wazuh.manager',['find','/var/ossec/etc/rules','-maxdepth','1','-type','f','-printf','%f\n']).stdout.strip(),
            'loopback':cmd(['ip','route','get','127.0.0.1']).stdout.strip()}
        # Do not include Filebeat authentication values in any output.
        text=data.pop('filebeat_archives_config')
        match=re.search(r'archives:\s*\n\s*enabled:\s*(\w+)',text)
        data['filebeat_archive_enabled']=match.group(1) if match else 'unrecognized'
        save_json(OUT/'audit.json',data)
        print(json.dumps(data,indent=2,ensure_ascii=False))
    elif mode=='configure':
        if BACKUP.exists():
            raise SystemExit('Backup exists; inspect it before reapplying configuration')
        BACKUP.mkdir(mode=0o700)
        shutil.copy2(manager,BACKUP/'manager.conf')
        fb=container('wazuh.manager',['cat','/etc/filebeat/filebeat.yml']).stdout
        (BACKUP/'filebeat.yml').write_text(fb)
        (BACKUP/'filebeat.yml').chmod(0o600)
        (BACKUP/'agent.conf').write_bytes(Path('/var/ossec/etc/ossec.conf').read_bytes())
        text=manager.read_text()
        if '<logall_json>' in text:
            text=re.sub(r'<logall_json>.*?</logall_json>','<logall_json>yes</logall_json>',text)
        else:
            text=text.replace('</global>','  <logall_json>yes</logall_json>\n</global>',1)
        manager.write_text(text)
        # Deployment uses a bind-mounted template; validate its actual container content too.
        live=container('wazuh.manager',['cat','/var/ossec/etc/ossec.conf']).stdout
        (BACKUP/'manager-live.conf').write_text(live)
        live=re.sub(r'<logall_json>.*?</logall_json>','<logall_json>yes</logall_json>',live)
        if '<logall_json>' not in live:
            live=live.replace('</global>','<logall_json>yes</logall_json>\n</global>',1)
        live_path=OUT/'manager-live.conf';live_path.write_text(live)
        cmd(COMPOSE+['cp',str(live_path),'wazuh.manager:/var/ossec/etc/ossec.conf'])
        new,count=re.subn(r'(archives:\s*\n\s*enabled:)\s*false',r'\1 true',fb)
        if count!=1:
            raise SystemExit('Unexpected Filebeat archives format; backup retained, use restore')
        path=OUT/'filebeat.yml';path.write_text(new);path.chmod(0o600)
        cmd(COMPOSE+['cp',str(path),'wazuh.manager:/etc/filebeat/filebeat.yml'])
        container('wazuh.manager',['/var/ossec/bin/wazuh-analysisd','-t'])
        container('wazuh.manager',['filebeat','test','config','-c','/etc/filebeat/filebeat.yml'])
        cmd(COMPOSE+['restart','wazuh.manager'])
        print('Archive collection and shipping enabled; persistent template/volumes updated; backup retained.')
    elif mode=='verify':
        token='soc-pipeline-'+uuid.uuid4().hex[:12]
        start=dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=3)
        url='http://127.0.0.1:8080/index.html?lab_run='+token
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url,timeout=10) as response:
            http_status=response.status
        body={'size':10,'query':{'bool':{'filter':[{'match_phrase':{'full_log':token}},
            {'term':{'location':'/var/log/nginx/soc_access.log'}},
            {'term':{'agent.name':'soc-ubuntu'}}]}},'sort':[{'timestamp':'desc'}]}
        found=None
        for attempt in range(30):
            try:
                found=query('wazuh-archives-*',body)
                if found['hits']['total']['value']>0:break
            except Exception:
                pass
            time.sleep(3)
        ssh=query('wazuh-alerts-*',{'size':5,'query':{'bool':{'filter':[
            {'term':{'rule.id':'5715'}},{'term':{'agent.name':'soc-ubuntu'}},
            {'term':{'location':'/var/log/auth.log'}},
            {'range':{'timestamp':{'gte':start.isoformat()}}}]}},'sort':[{'timestamp':'desc'}]})
        raw={'run_id':token,'http_status':http_status,'archive_query':body,'archive_result':found,'ssh_result':ssh}
        save_json(OUT/(token+'.json'),raw)
        web_hits=found['hits']['hits'] if found else []
        # Avoid printing raw usernames, network addresses or full events.
        summary={'run_id':token,'http_status':http_status,
            'nginx_archive_matches':len(web_hits),'ssh_success_matches':len(ssh['hits']['hits']),
            'nginx_event_ids':[h['_source'].get('id') for h in web_hits],
            'nginx_index_ids':[h['_id'] for h in web_hits],
            'ssh_alert_ids':[h['_source'].get('id') for h in ssh['hits']['hits']],
            'passed':bool(web_hits) and http_status==200 and bool(ssh['hits']['hits'])}
        save_json(OUT/'latest-summary.json',summary)
        save_json(OUT/(token+'-summary.json'),summary)
        print(json.dumps(summary,indent=2))
        if not summary['passed']:raise SystemExit(1)
    elif mode=='diagnose':
        result={}
        prior=OUT/'query-error.txt'
        if prior.exists():
            result['previous_error_is_dns']=any(s in prior.read_text() for s in ['Name or service not known','Temporary failure in name resolution'])
        for index in ['wazuh-archives-*','wazuh-alerts-*']:
            try:
                response=query(index,{'size':0})
                result[index]={'hits':response['hits']['total']}
            except Exception as exc:
                result[index]={'error_type':type(exc).__name__,'http_code':getattr(exc,'code',None)}
                # Detailed diagnostic belongs only in the private guest evidence directory.
                (OUT/'query-error.txt').write_text(str(exc))
        for path in ['/var/ossec/logs/archives/archives.json','/var/ossec/logs/filebeat/filebeat']:
            response=container('wazuh.manager',['stat','-c','%s',path],False)
            result[path]={'exists':response.returncode==0,'bytes':response.stdout.strip()}
        logs=cmd(COMPOSE+['logs','--tail','100','wazuh.manager'],False)
        (OUT/'manager-diagnostic.log').write_text(logs.stdout+logs.stderr)
        print(json.dumps(result,indent=2))
    elif mode=='restore':
        shutil.copy2(BACKUP/'manager.conf',manager)
        cmd(COMPOSE+['cp',str(BACKUP/'manager-live.conf'),'wazuh.manager:/var/ossec/etc/ossec.conf'])
        cmd(COMPOSE+['cp',str(BACKUP/'filebeat.yml'),'wazuh.manager:/etc/filebeat/filebeat.yml'])
        cmd(COMPOSE+['restart','wazuh.manager'])
        print('Manager template/live config and Filebeat restored; stored evidence preserved.')


if __name__=='__main__':
    main()
