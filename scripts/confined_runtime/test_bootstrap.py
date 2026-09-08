"""Execute the real bootstrap against hostile, but syntactically valid inputs."""
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import policy_identity, watchdog

ENTRY = Path(__file__).parent / 'packaging/entry.py'
FLAGS = ['-I', '-S', '-B', '-X', 'pycache_prefix=/dev/null']


class BootstrapTests(unittest.TestCase):
    def test_imports_execute_only_source_without_site_hooks_or_root_shadowing(self):
        for invalidation in (py_compile.PycInvalidationMode.TIMESTAMP,
                             py_compile.PycInvalidationMode.UNCHECKED_HASH):
            with self.subTest(invalidation=invalidation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                package = root / 'scripts/confined_runtime'
                (package / 'packaging').mkdir(parents=True)
                shutil.copyfile(ENTRY, package / 'packaging/entry.py')
                site = root / f'venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages'
                site.mkdir(parents=True)
                hostile = 'raise RuntimeError("unexpected code executed")\n'
                (root / 'pathlib.py').write_text(hostile)
                (root / 'scripts/__init__.py').write_text(hostile)
                (site / 'sitecustomize.py').write_text(hostile)
                (site / 'hostile.pth').write_text('import sitecustomize\n')
                source = site / 'probe.py'
                source.write_text('VALUE = "old"\n')
                timestamp = source.stat().st_mtime_ns
                py_compile.compile(str(source), doraise=True, invalidation_mode=invalidation)
                source.write_text('VALUE = "new"\n')
                os.utime(source, ns=(timestamp, timestamp))
                ghost = site / 'ghost.py'
                ghost.write_text(hostile)
                py_compile.compile(str(ghost), cfile=str(site / 'ghost.pyc'), doraise=True)
                ghost.unlink()
                (package / 'service.py').write_text('''import probe
import sys
assert probe.VALUE == 'new'
assert 'sitecustomize' not in sys.modules
try:
    import ghost
except ModuleNotFoundError:
    pass
else:
    raise AssertionError('sourceless import accepted')
def main():
    print('source-only')
    return 0
''')
                result = subprocess.run([sys.executable, *FLAGS, str(package / 'packaging/entry.py'), 'check'],
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'source-only\n')

    def test_detached_watchdog_starts_through_same_bootstrap(self):
        process = watchdog.start('archon-confined-11111111-1111-4111-8111-111111111111',
                                 900, 'sha256:' + 'a' * 64)
        try:
            self.assertIsNone(process.poll())
            self.assertEqual(process.args[1:7], [*FLAGS, str(ENTRY.resolve())])
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_missing_bootstrap_flags_fail_before_application_imports(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(ENTRY), 'check'],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported_python_bootstrap', result.stderr)

    def test_directory_aliases_cannot_hide_executable_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site = root / 'site-packages'
            site.mkdir()
            target = root / 'target'
            target.mkdir()
            (target / '__init__.py').write_text('VALUE = "first"')
            (site / 'unregistered').symlink_to(target, target_is_directory=True)
            with patch.object(sys, 'path', [*sys.path, str(site)]):
                with self.assertRaisesRegex(ValueError, 'unsupported_import_directory_alias'):
                    policy_identity.revision()
                (target / '__init__.py').write_text('VALUE = "other"')
                with self.assertRaisesRegex(ValueError, 'unsupported_import_directory_alias'):
                    policy_identity.revision()
            package = root / 'scripts/confined_runtime/packaging'
            package.mkdir(parents=True)
            shutil.copyfile(ENTRY, package / 'entry.py')
            installed_site = root / f'venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages'
            installed_site.parent.mkdir(parents=True)
            installed_site.symlink_to(site, target_is_directory=True)
            result = subprocess.run([sys.executable, *FLAGS, str(package / 'entry.py'), 'check'],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unsupported_import_directory_alias', result.stderr)

    def test_unregistered_source_and_extensions_change_identity(self):
        with tempfile.TemporaryDirectory(suffix='site-packages') as directory:
            site = Path(directory) / 'site-packages'
            site.mkdir()
            with patch.object(sys, 'path', [*sys.path, str(site)]):
                before = policy_identity.revision()
                for filename in ('unregistered.py', 'unregistered.so'):
                    path = site / filename
                    path.write_bytes(b'first')
                    first = policy_identity.revision()
                    self.assertNotEqual(first, before)
                    path.write_bytes(b'other')
                    self.assertNotEqual(policy_identity.revision(), first)
                    path.unlink()
                self.assertEqual(policy_identity.revision(), before)
