"""Persist Filebeat's supported -M archives override in the pinned image service."""
import importlib.util
from pathlib import Path
import re
import shutil
import sys
import yaml

spec=importlib.util.spec_from_file_location('pipeline',Path(__file__).with_name('phase1-log-pipeline.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
if p.cmd(['hostname']).stdout.strip()!='soc-ubuntu':raise SystemExit('Wrong guest')
stack=p.STACK
backup=p.ROOT/'detection-lab/backup'
config=stack/'compose.lab.yml'
saved=backup/'compose.before-archives.yml'
if len(sys.argv)>1 and sys.argv[1]=='restore':
    if not saved.exists():raise SystemExit('No archive launcher backup available')
    shutil.copy2(saved,config)
    p.cmd(p.COMPOSE+['up','-d','--no-deps','wazuh.manager'])
    print('Archive launcher override removed; rule mount preserved. Recheck archives state before further experiments.')
    raise SystemExit(0)
if len(sys.argv)>1 and sys.argv[1]!='configure':raise SystemExit('Use configure or restore')
if saved.exists():raise SystemExit('Archive persistence patch already applied; inspect before retrying')
shutil.copy2(config,saved)
original=p.container('wazuh.manager',['cat','/etc/services.d/filebeat/run']).stdout
(backup/'filebeat-run').write_text(original)
if original.count('/usr/share/filebeat/bin/filebeat -e')!=1:
    raise SystemExit('Unexpected pinned image service launcher')
patched=original.replace('/usr/share/filebeat/bin/filebeat -e',
    '/usr/share/filebeat/bin/filebeat -e -M wazuh.archives.enabled=true',1)
source=stack/'config/soc_lab/filebeat-run'
source.write_text(patched);source.chmod(0o755)
compose=yaml.safe_load(config.read_text())
compose['services']['wazuh.manager']['volumes'].append('./config/soc_lab/filebeat-run:/etc/services.d/filebeat/run:ro')
config.write_text(yaml.safe_dump(compose,sort_keys=False))
p.cmd(p.COMPOSE+['config','--quiet'])
p.cmd(p.COMPOSE+['up','-d','--no-deps','wazuh.manager'])
print('Pinned Filebeat launcher persisted with -M wazuh.archives.enabled=true; previous Compose and launcher backed up.')
