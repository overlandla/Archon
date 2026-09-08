"""Provision fresh bounded FUSE storage on an authorized dedicated test LXC."""
import os
import pathlib
import subprocess

if os.geteuid() != 0:
    raise SystemExit("dedicated_test_host_root_required")
root=pathlib.Path('/var/lib/archon-conformance')
if not root.is_dir() or root.stat().st_mode & 0o077:
    raise SystemExit('root_private_conformance_directory_required')
for name, size, target in [('journal','1G','/var/lib/archon-confined'),('docker','16G','/var/lib/archon-confined-docker')]:
    image=root/(name+'.ext4')
    unit_path = pathlib.Path('/etc/systemd/system') / f'archon-conformance-{name}-storage.service'
    if image.exists() or pathlib.Path(target).exists() or unit_path.exists():
        raise SystemExit('Refusing to replace existing test image')
    subprocess.run(['truncate','-s',size,str(image)],check=True)
    image.chmod(0o600)
    subprocess.run(['mkfs.ext4','-q',str(image)],check=True)
    pathlib.Path(target).mkdir(mode=0o700)
    unit=f'''[Unit]
Description=Disposable Archon {name} filesystem
DefaultDependencies=no
After=local-fs-pre.target
Before=local-fs.target archon-confined-containerd.service archon-confined-docker.service archon-confined-cleanup.service archon-confined.service
Conflicts=umount.target
Before=umount.target

[Service]
Type=forking
ExecStart=/usr/bin/fuse2fs -o rw,allow_other {image} {target}
ExecStop=/usr/bin/umount {target}
TimeoutStopSec=60
KillMode=control-group

[Install]
WantedBy=local-fs.target
'''
    path=pathlib.Path('/etc/systemd/system')/f'archon-conformance-{name}-storage.service'
    path.write_text(unit)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now',path.name],check=True)
    subprocess.run(['mountpoint','-q',target],check=True)
    pathlib.Path(target,'lost+found').rmdir()
    if name=='journal':
        subprocess.run(['chown','archon-confined:archon-confined',target],check=True)
    pathlib.Path(target).chmod(0o700)
