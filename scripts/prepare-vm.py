"""Create a dedicated VMware Ubuntu cloud VM; never modify an existing VM.

Run with the Python interpreter containing requests and pycdlib.
This step downloads and verifies the Ubuntu image and creates a 50 GiB sparse
disk. Boot is deliberately separate so host memory can be checked first.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import requests
import pycdlib
import yaml

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / 'local-evidence'
VM = Path('E:/SOC-Lab/SOC-Ubuntu')
BASE = 'https://cloud-images.ubuntu.com/releases/jammy/release/'
NAME = 'ubuntu-22.04-server-cloudimg-amd64.vmdk'
VMWARE = Path('E:/vmware')


def run(args):
    subprocess.run([str(a) for a in args], check=True)


def download(url, target):
    part = target.with_suffix(target.suffix + '.part')
    offset = part.stat().st_size if part.exists() else 0
    with requests.get(url, headers={'Range': f'bytes={offset}-'} if offset else {},
                      stream=True, timeout=(30, 90)) as response:
        response.raise_for_status()
        append = response.status_code == 206 and offset > 0
        total = int(response.headers.get('Content-Length', 0)) + (offset if append else 0)
        size = offset if append else 0
        last = 0
        with part.open('ab' if append else 'wb') as stream:
            for block in response.iter_content(1024 * 1024):
                stream.write(block)
                size += len(block)
                if time.monotonic() - last > 15:
                    print(f'Downloaded {size / 2**20:.0f}/{total / 2**20:.0f} MiB', flush=True)
                    last = time.monotonic()
    part.replace(target)


def main():
    PRIVATE.mkdir(exist_ok=True)
    VM.mkdir(parents=True, exist_ok=True)
    if (VM / 'SOC-Ubuntu.vmx').exists():
        raise SystemExit('Dedicated VM already exists; refusing to overwrite it.')
    response = requests.get(BASE + 'SHA256SUMS', timeout=60)
    response.raise_for_status()
    checksums = response.text
    expected = next(line.split()[0] for line in checksums.splitlines()
                    if line.split()[-1].lstrip('*') == NAME)
    (PRIVATE / 'ubuntu-SHA256SUMS').write_text(checksums)
    image = VM / NAME
    if not image.exists():
        download(BASE + NAME, image)
    actual = hashlib.file_digest(image.open('rb'), 'sha256').hexdigest()
    if actual != expected:
        raise SystemExit('Ubuntu SHA256 mismatch; refusing to use image.')
    print('Official Ubuntu image SHA256 verified.', flush=True)
    disk = VM / 'SOC-Ubuntu.vmdk'
    if disk.exists():
        raise SystemExit('Target disk already exists; refusing to overwrite it.')
    run([VMWARE / 'vmware-vdiskmanager.exe', '-r', image, '-t', '0', disk])
    run([VMWARE / 'vmware-vdiskmanager.exe', '-x', '50GB', disk])
    key = PRIVATE / 'soc_ed25519'
    if not key.exists():
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'soc-local-lab', '-f', key])
    public = key.with_suffix('.pub').read_text().strip()
    config = {
        'hostname': 'soc-ubuntu', 'manage_etc_hosts': True,
        'timezone': 'Asia/Shanghai', 'ssh_pwauth': False, 'disable_root': True,
        'users': [{'name': 'soc', 'shell': '/bin/bash', 'groups': ['sudo'],
                   'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True,
                   'ssh_authorized_keys': [public]}],
        'growpart': {'mode': 'auto', 'devices': ['/'], 'ignore_growroot_disabled': False},
        'resize_rootfs': True,
        'runcmd': [['systemctl', 'enable', '--now', 'open-vm-tools']],
    }
    user_data = ('#cloud-config\n' + yaml.safe_dump(config)).encode()
    meta_data = b'instance-id: soc-lab-20261105\nlocal-hostname: soc-ubuntu\n'
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, vol_ident='cidata', joliet=3, rock_ridge='1.09')
    for name, data, path in [('user-data', user_data, '/USERDATA.;1'),
                              ('meta-data', meta_data, '/METADATA.;1')]:
        iso.add_fp(io.BytesIO(data), len(data), iso_path=path,
                   rr_name=name, joliet_path='/' + name)
    iso.write(str(VM / 'seed.iso'))
    iso.close()
    vmx = '''.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
displayName = "SOC-Ubuntu"
guestOS = "ubuntu-64"
firmware = "efi"
memsize = "8192"
numvcpus = "4"
cpuid.coresPerSocket = "4"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "SOC-Ubuntu.vmdk"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "seed.iso"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"
ethernet0.startConnected = "TRUE"
usb.present = "FALSE"
sound.present = "FALSE"
tools.syncTime = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
'''
    (VM / 'SOC-Ubuntu.vmx').write_text(vmx, encoding='utf-8')
    (PRIVATE / 'vm-manifest.json').write_text(json.dumps({
        'image_url': BASE + NAME, 'sha256': actual,
        'vmx': str(VM / 'SOC-Ubuntu.vmx'), 'disk_limit_gib': 50,
        'memory_mib': 8192, 'vcpus': 4, 'status': 'created-not-booted',
    }, indent=2))
    print('VM created: 4 vCPU, 8192 MiB RAM, 50 GiB sparse disk. Not booted.', flush=True)


if __name__ == '__main__':
    main()
