"""Local transport for this lab. Never print connection credentials."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / 'local-evidence'


def connection():
    info=json.loads((PRIVATE/'access.json').read_text(encoding='utf-8-sig'))
    opts=['-i',str(PRIVATE/'soc_ed25519'),'-o','BatchMode=yes',
          '-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts')]
    return opts, 'soc@'+info['ip']


def run(command, timeout=90):
    opts,target=connection()
    return subprocess.run(['ssh',*opts,target,command],capture_output=True,timeout=timeout)


def upload(path):
    opts,target=connection()
    subprocess.run(['scp',*opts,str(path),target+':/tmp/'+Path(path).name],
                   check=True,capture_output=True,timeout=60)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('script',type=Path)
    parser.add_argument('--argument',default='audit',choices=['audit','configure','verify','restore','diagnose','reconcile'])
    args=parser.parse_args()
    try:
        if args.script.name in {'detection-lab.py', 'fix-archive-persistence.py', 'ssh-sequence-lab.py',
                                'suricata-lab.py', 'threat-intel-fim.py'}:
            # These guest scripts import the pipeline module beside themselves.
            # A guest reboot may clear the previous upload under /tmp.
            upload(Path(__file__).with_name('phase1-log-pipeline.py'))
        if args.script.name == 'suricata-lab.py' and args.argument == 'configure':
            for name in ('yaml', 'rules', 'service', 'logrotate'):
                upload(ROOT/'config/suricata'/('soc-suricata.' + name))
        upload(args.script)
        result=run('sudo python3 /tmp/'+args.script.name+' '+args.argument,timeout=240)
    except (subprocess.TimeoutExpired,subprocess.CalledProcessError) as exc:
        (PRIVATE/'transport-error.txt').write_text(repr(exc),encoding='utf-8')
        raise SystemExit('Transport failed or timed out; details retained privately.') from None
    PRIVATE.mkdir(exist_ok=True)
    (PRIVATE/('last-'+args.script.stem+'.out')).write_bytes(result.stdout)
    (PRIVATE/('last-'+args.script.stem+'.err')).write_bytes(result.stderr)
    if result.returncode:
        print('Remote operation failed; private stdout/stderr retained. Exit:',result.returncode)
    else:
        print(result.stdout.decode())
    raise SystemExit(result.returncode)
