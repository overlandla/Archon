"""Protected operator composition for the separate confined runtime service.

Public configuration is data, never an import path or executable callback. The
adapter's independent complete-release registry remains the activation gate.
"""
import argparse
import fcntl
import os
import signal
import stat
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from .admission import Release, Supervisor
from .closure import inspect as inspect_closure
from .control import Server
from .https_transport import Origin, parse_json
from .journal import Journal
from .model_broker import ModelPolicy
from .publication import Policy as PublicationPolicy
from .runtime import Profile, Runtime
from .source_authority import TheseusAuthority

RELEASE_ROOT = Path('/opt/archon-confined/release')
STATE_ROOT = Path('/var/lib/archon-confined')
CONFIG = Path('/etc/archon-confined/profile.json')
SCRATCH = Path('/tmp/archon-confined-runtime/work')
CREDENTIALS = ('ingress', 'theseus', 'github', 'model')


def protected(path: Path, *, owner: int, private=False):
    """Check canonical parents and final ownership before opening trusted data.

Only root can replace ancestors. Private state itself belongs to the service;
workers never receive this directory or the Docker control socket as a mount.
    """
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('noncanonical_protected_path')
    for parent in reversed(path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            # /tmp is the one sticky system ancestor, never a trusted file root.
            if parent != Path('/tmp') or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
                raise ValueError('unprotected_parent')
    info = path.stat()
    if info.st_uid != owner or info.st_mode & (0o077 if private else 0o022):
        raise ValueError('unprotected_path')
    return info


def installation():
    protected(RELEASE_ROOT, owner=0)
    for path in RELEASE_ROOT.rglob('*'):
        # venv interpreter/lib links may resolve to root-protected OS paths;
        # editable installs and worker-owned source paths are never supported.
        resolved = path.resolve(strict=True)
        info = protected(resolved, owner=0)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('unsupported_release_file')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError('linked_release_file')
    package = RELEASE_ROOT / 'scripts/confined_runtime/packaging'
    runc_rule = Path('/etc/apparmor.d/local/runc')
    protected(runc_rule, owner=0)
    if runc_rule.read_bytes() != (package / 'runc-local.conf').read_bytes():
        raise ValueError('installed_runtime_rule_mismatch')
    units = sorted(p for p in package.iterdir() if p.suffix in {'.service', '.slice', '.mount'})
    for source in units:
        installed = Path('/etc/systemd/system') / source.name
        protected(installed, owner=0)
        if installed.read_bytes() != source.read_bytes():
            raise ValueError('installed_unit_mismatch')
        result = subprocess.run(['/usr/bin/systemctl', 'show', source.name, '--property=DropInPaths', '--property=NeedDaemonReload'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, check=True, timeout=5)
        if set(result.stdout.decode().splitlines()) != {'DropInPaths=', 'NeedDaemonReload=no'}:
            raise ValueError('unreviewed_unit_override')


def private_state():
    protected(STATE_ROOT, owner=os.geteuid(), private=True)
    # Packaging requires a dedicated bounded filesystem, not a quota promise.
    fs = os.statvfs(STATE_ROOT)
    if fs.f_blocks * fs.f_frsize > 2 * 1024 ** 3:
        raise ValueError('unbounded_journal_filesystem')
    for path in STATE_ROOT.iterdir():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('unprotected_journal_file')


def public_profile(path: Path):
    info = protected(path, owner=0)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
        raise ValueError('invalid_profile_file')
    value = parse_json(path.read_bytes())
    fields = {'format', 'release', 'port', 'source', 'model', 'model_origin',
              'selected_repository', 'owner', 'repository', 'repository_id',
              'allowed_paths', 'automation_mode'}
    if not isinstance(value, dict) or set(value) != fields or value['format'] != 'archon-operator-profile-v1':
        raise ValueError('unsupported_operator_profile')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('invalid_private_port')
    if not isinstance(value['source'], dict) or set(value['source']) != {'deployment', 'project'}:
        raise ValueError('invalid_source')
    if (not isinstance(value['allowed_paths'], list) or not value['allowed_paths']
            or not all(isinstance(p, str) for p in value['allowed_paths'])
            or len(set(value['allowed_paths'])) != len(value['allowed_paths'])):
        raise ValueError('invalid_allowed_paths')
    return value


def credentials(directory: Path):
    # systemd owns this per-unit read-only mount. It may be owned by root or by
    # the unit user; no public configuration can select alternate secret paths.
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise ValueError('invalid_credential_directory')
    info = directory.stat()
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077:
        raise ValueError('unprotected_credential_directory')
    result = {}
    for name in CREDENTIALS:
        path = directory / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o077 or not 32 <= info.st_size <= 8192):
            raise ValueError('invalid_credential_file')
        value = path.read_text().removesuffix('\n')
        if not 32 <= len(value) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError('invalid_credential_value')
        result[name] = value
    return result


def compose(value, secrets, capture=RELEASE_ROOT / 'capture'):
    release = dict(value['release'])
    if release.pop('format', None) != 'archon-confined-experimental-v1':
        raise ValueError('unsupported_release_format')
    release = Release(**release)
    profile = Profile(release, 'sha256:' + release.confinement_revision, capture,
        value['model'], TheseusAuthority(**value['source'], credential=secrets['theseus']),
        value['selected_repository'], value['owner'], value['repository'], value['repository_id'],
        frozenset(value['allowed_paths']), value['automation_mode'], secrets['github'],
        value['model_origin'], secrets['model'])
    # Validate the same policies consumed later, before opening the listener or
    # creating the journal. A declaration of automation isolation is not proof.
    Origin('api.github.com', secrets['github'])
    model = ModelPolicy(profile.model_origin, profile.model, profile.model_credential)
    model.close()
    PublicationPolicy(profile.owner, profile.repository, profile.repository_id,
        '00000000-0000-0000-0000-000000000001', profile.selected_repository['base'],
        'a' * 40, 'a' * 40, profile.allowed_paths, 'a' * 40, profile.automation_mode).validate()
    profile.validate()
    inspect_closure(capture, release.identity, release.closure_revision)
    return profile


@contextmanager
def exclusive_owner(path: Path):
    # The private state parent prevents replacement; O_NOFOLLOW rejects stale
    # operator mistakes. This lock supplements, never replaces, journal fences.
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('unprotected_owner_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('check', 'serve', 'cleanup'))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if os.geteuid() == 0:
            raise ValueError('runtime_requires_distinct_identity')
        installation()
        private_state()
        if args.mode == 'cleanup':
            from .cleanup_service import serve
            with exclusive_owner(STATE_ROOT / 'cleanup.lock'):
                serve(Journal(STATE_ROOT / 'journal.sqlite'))
            return 0
        protected(SCRATCH, owner=os.geteuid(), private=True)
        # Docker resolves bind sources in the host namespace: never use
        # PrivateTmp or a service-private mount for these staging paths.
        os.environ['TMPDIR'] = str(SCRATCH)
        import tempfile
        tempfile.tempdir = str(SCRATCH)
        value = public_profile(CONFIG)
        secret_values = credentials(Path(os.environ['CREDENTIALS_DIRECTORY']))
        profile = compose(value, secret_values)
        if args.mode == 'check':
            print('operator_profile_validated; release_approval_not_implied')
            return 0
        with exclusive_owner(STATE_ROOT / 'admission.lock'):
            journal = Journal(STATE_ROOT / 'journal.sqlite')
            server = Server(value['port'], Supervisor(journal, profile.release, Runtime(journal, profile)),
                            profile.authority.deployment, profile.authority.project, secret_values['ingress'])
            def stop(_signum, _frame):
                server.stopped.set()
                threading.Thread(target=server.shutdown, daemon=True).start()
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            try:
                server.serve_forever(poll_interval=0.5)
            finally:
                server.server_close()
        return 0
    except Exception:
        # Neither exception text nor traceback may disclose profile or secrets.
        print('confined_service_unavailable', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
