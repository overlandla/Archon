import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from .admission import Release
from .cleanup_service import ready, sweep
from .journal import Journal
from .runtime import NATIVE_CONFIG, Profile
from .service import (
    compose,
    credentials,
    exclusive_owner,
    main,
    private_state,
    protected,
    public_profile,
)
from .source_authority import TheseusAuthority


class ServiceTests(unittest.TestCase):
    def test_credentials_reject_links_public_modes_and_header_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('ingress', 'theseus', 'github', 'model'):
                (root / name).write_text('s' * 32 + '\n')
                (root / name).chmod(0o600)
            self.assertEqual(credentials(root)['model'], 's' * 32)
            (root / 'model').chmod(0o644)
            with self.assertRaises(ValueError):
                credentials(root)
            (root / 'model').chmod(0o600)
            (root / 'model').write_text('s' * 32 + '\nInjected: header')
            with self.assertRaises(ValueError):
                credentials(root)
            (root / 'model').unlink()
            (root / 'model').symlink_to(root / 'github')
            with self.assertRaises(ValueError):
                credentials(root)

    def test_duplicate_owner_and_symlink_lock_fail_without_replacing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owner'
            with exclusive_owner(path):
                with self.assertRaises(BlockingIOError), exclusive_owner(path):
                    self.fail('duplicate owner entered')
            with exclusive_owner(path):
                pass
            path.unlink()
            target = Path(directory) / 'target'
            target.write_text('preserve')
            path.symlink_to(target)
            with self.assertRaises(OSError), exclusive_owner(path):
                self.fail('symlink lock entered')
            self.assertEqual(target.read_text(), 'preserve')

    def test_protected_paths_reject_public_write_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            protected(path, owner=os.geteuid(), private=True)
            path.chmod(0o777)
            with self.assertRaises(ValueError):
                protected(path, owner=os.geteuid(), private=True)
            path.chmod(0o700)
            link = path / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                protected(link, owner=os.geteuid())

    def test_state_refuses_unbounded_filesystem_before_journal_open(self):
        with patch('scripts.confined_runtime.service.protected'), patch('scripts.confined_runtime.service.os.statvfs') as filesystem:
            filesystem.return_value.f_blocks = 1024 ** 3
            filesystem.return_value.f_frsize = 4096
            with self.assertRaisesRegex(ValueError, 'unbounded_journal_filesystem'):
                private_state()

    def profile(self, capture):
        release = Release('proof', *('a' * 64 for _ in range(7)))
        release = replace(release, native_configuration_revision=hashlib.sha256(NATIVE_CONFIG.encode()).hexdigest())
        profile = Profile(release, 'sha256:' + 'a' * 64, capture, 'fixture-model',
            TheseusAuthority('https://source.invalid', 1000, 's' * 32),
            {'canonical_ref': 'github:owner/repo', 'repository': '/approved/repo', 'worktree_root': '/approved/worktrees', 'base': 'main'},
            'owner', 'repo', 1, frozenset({'src/main.py'}), 'operator-isolated-actions-disabled',
            's' * 32, 'https://model.invalid', 's' * 32)
        release = replace(release, authority_configuration_revision=profile.configuration_revision())
        return {'format': 'archon-operator-profile-v1', 'release': release.selection(), 'port': 8788,
                'source': {'deployment': profile.authority.deployment, 'project': 1000},
                **{key: getattr(profile, key) for key in ('model', 'model_origin', 'selected_repository', 'owner', 'repository', 'repository_id', 'automation_mode')},
                'allowed_paths': sorted(profile.allowed_paths)}

    def test_exact_profile_composition_and_no_dynamic_configuration(self):
        with tempfile.TemporaryDirectory() as directory, patch('scripts.confined_runtime.runtime.policy_revision', return_value='a' * 64), patch('scripts.confined_runtime.service.inspect_closure'):
            root = Path(directory)
            value = self.profile(root)
            secrets = {name: 's' * 32 for name in ('ingress', 'theseus', 'github', 'model')}
            self.assertEqual(compose(value, secrets, root).release.selection(), value['release'])
            changed = {**value, 'allowed_paths': ['deploy.py']}
            with self.assertRaises(RuntimeError):
                compose(changed, secrets, root)
            with self.assertRaises(ValueError):
                compose({**value, 'release': {**value['release'], 'format': 'unknown'}}, secrets, root)
            path = root / 'profile.json'
            # Permission validation is tested separately. This test isolates the
            # parser from host ownership without bypassing profile validation.
            with patch('scripts.confined_runtime.service.protected', side_effect=lambda p, **_: p.stat()):
                path.write_text(json.dumps(value))
                self.assertEqual(public_profile(path), value)
                path.write_text(json.dumps({**value, 'credentials': secrets}))
                with self.assertRaises(ValueError):
                    public_profile(path)
                path.write_text('{"format":"a","format":"b"}')
                with self.assertRaises(ValueError):
                    public_profile(path)

    def test_failure_diagnostic_does_not_print_exception_or_credentials(self):
        output = io.StringIO()
        with patch('sys.argv', ['service', 'check']), patch('scripts.confined_runtime.service.os.geteuid', return_value=1000), patch('scripts.confined_runtime.service.protected', side_effect=ValueError('secret-do-not-print')), contextlib.redirect_stderr(output):
            self.assertEqual(main(), 1)
        self.assertEqual(output.getvalue(), 'confined_service_unavailable\n')


class DurableCleanupTests(unittest.TestCase):
    def test_restart_and_daemon_failure_keep_cleanup_without_reinvocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'journal'
            journal = Journal(path)
            row = journal.admit('https://source.invalid', 1000, 'correlation', {})
            row = journal.transition(row['run_id'], 0, 'check')
            row = journal.transition(row['run_id'], 1, 'invoke')
            owner = {'name': 'archon-confined-' + row['run_id'], 'image': 'sha256:' + 'a' * 64, 'expires_at': 100}
            journal.record_fact(row['run_id'], 'container', owner)
            calls = []
            def remove(name, image):
                calls.append((name, image))
                return len(calls) > 1
            self.assertEqual(sweep(journal, now=99, remove=remove), (0, True))
            self.assertEqual(calls, [])
            self.assertEqual(sweep(journal, now=100, remove=remove), (0, False))
            reopened = Journal(path)
            self.assertEqual(sweep(reopened, now=101, remove=remove), (0, True))
            # Absence is rechecked: a delayed daemon creation cannot lose cleanup.
            self.assertEqual(sweep(reopened, now=102, remove=remove), (0, True))
            self.assertEqual(len(calls), 3)
            current, facts = reopened.inspect_run(row['run_id'])
            self.assertEqual(current['state'], 'invoking')
            self.assertEqual(current['revision'], 2)
            self.assertEqual(facts, {'container': owner})

    def test_bad_owner_never_reaches_daemon_and_does_not_hide_later_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(Path(directory) / 'journal')
            for n in range(33):
                row = journal.admit('https://source.invalid', 1000, str(n), {})
                journal.transition(row['run_id'], 0, 'check')
                journal.transition(row['run_id'], 1, 'invoke')
                journal.record_fact(row['run_id'], 'container', {'name': '../../foreign'} if n == 0 else {
                    'name': 'archon-confined-' + row['run_id'], 'image': 'sha256:' + 'a' * 64, 'expires_at': 0})
            calls = []
            def remove(*args):
                calls.append(args)
                return True
            cursor, healthy = sweep(journal, now=100, remove=remove)
            self.assertFalse(healthy)
            self.assertGreater(cursor, 0)
            self.assertEqual(len(calls), 31)
            self.assertEqual(sweep(journal, after=cursor, now=100, remove=remove), (0, True))
            self.assertEqual(len(calls), 32)

    def test_cleanup_readiness_uses_supervisor_socket(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
            path = str(Path(directory) / 'notify')
            receiver.bind(path)
            receiver.settimeout(1)
            with patch.dict(os.environ, {'NOTIFY_SOCKET': path}):
                ready()
            self.assertEqual(receiver.recv(64), b'READY=1')
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
                ready()

    def test_unknown_journal_version_fails_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'journal'
            journal = Journal(path)
            with journal.connect() as connection:
                connection.execute('PRAGMA user_version=99')
            with self.assertRaises(ValueError):
                Journal(path)


class UnitGraphTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd analyzer unavailable')
    def test_unit_dependency_graph_with_executable_existence_fixtures(self):
        # This checks systemd parsing and ordering, not installed enforcement.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            names = []
            for source in (Path(__file__).parent / 'packaging').iterdir():
                if source.suffix in {'.service', '.slice', '.mount'}:
                    shutil.copyfile(source, units / source.name)
                    names.append(source.name)
            for target in ('sysinit', 'basic', 'shutdown', 'sockets', 'timers', 'paths', 'network-online', 'multi-user', 'local-fs', 'umount'):
                (units / (target + '.target')).write_text('[Unit]\nDescription=Verification fixture\nDefaultDependencies=no\n')
            for binary in ('opt/archon-confined/release/venv/bin/python', 'usr/bin/dockerd', 'usr/bin/systemd-tmpfiles'):
                destination = root / binary
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile('/usr/bin/true', destination)
                destination.chmod(0o755)
            result = subprocess.run(['systemd-analyze', 'verify', '--root=' + str(root), *names], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
