"""Opt-in black-box checks for the installed synthetic conformance host."""
import argparse
import copy
import http.client
import json
import os
import ssl
import subprocess
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path('/var/lib/archon-conformance')
DOCKER = ['docker', '--host', 'unix:///run/archon-confined-docker/docker.sock']


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=120, **kwargs)


class Checks:
    def __init__(self):
        self.selection = json.loads((ROOT / 'selection.json').read_text())
        self.source = self.selection['source']
        self.secret = {p.name: p.read_text() for p in Path('/etc/archon-confined/credentials').iterdir()}
        self.results = []
        report = ROOT / 'installed-checks.json'
        if report.exists():
            previous = json.loads(report.read_text())
            if previous['release'] != self.selection['release']:
                raise RuntimeError('previous_evidence_has_different_release')
            self.results = previous['cases']

    def record(self, name, **facts):
        self.results.append({'case': name, 'passed': True, **facts})
        (ROOT / 'installed-checks.json').write_text(json.dumps({'full_runtime_conformance': False, 'live_acceptance': False,
            'release': self.selection['release'], 'cases': self.results}, indent=2))
        print(name + ': passed', flush=True)

    def control(self, path, value, token=True):
        connection = http.client.HTTPConnection('127.0.0.1', 8788, timeout=15)
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + self.secret['ingress']
        connection.request('POST', path, json.dumps(value), headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def fixture(self, mode):
        connection = http.client.HTTPSConnection('theseus.example.test', timeout=15, context=ssl.create_default_context())
        connection.request('POST', '/fixture/mode', json.dumps({'mode': mode}),
            {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.secret['theseus']})
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()

    def wait_ready(self):
        for _ in range(90):
            try:
                status, row = self.control('/v1/contract', {'source': self.source})
                if status == 200:
                    assert row['release'] == self.selection['release']
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(1)
        raise RuntimeError('service_not_ready')

    def admit(self, name):
        correlation = name + '-' + str(uuid4())
        (ROOT / 'pending-correlation').write_text(correlation)
        status, row = self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})
        assert status == 202, status
        return correlation, row

    def inspect(self, identity):
        status, row = self.control('/v1/inspect', {'source': self.source, 'run_id': identity})
        assert status == 200
        return row

    def terminal(self, row):
        for _ in range(180):
            row = self.inspect(row['run_id'])
            if row['state'] in ('finished', 'rejected', 'uncertain'):
                return row
            time.sleep(2)
        raise RuntimeError('run_did_not_terminate')

    def enforcement(self):
        self.wait_ready()
        info = json.loads(subprocess.check_output([*DOCKER, 'info', '--format', '{{json .}}']))
        assert info['Containerd']['Address'] == '/run/archon-confined-containerd/containerd.sock'
        assert info['Driver'] == 'fuse-overlayfs'
        assert info['DockerRootDir'] == '/var/lib/archon-confined-docker'
        self.record('explicit-private-containerd-and-bounded-fuse-storage')

    def nominal(self):
        self.wait_ready()
        self.fixture('reset')
        retained = ROOT / 'last-correlation'
        if retained.exists():
            correlation = retained.read_text()
            status, lookup = self.control('/v1/lookup', {'source': self.source, 'correlation_id': correlation})
            assert status == 200 and lookup['complete'] and len(lookup['runs']) == 1
            row = lookup['runs'][0]
        else:
            correlation = 'installed-nominal-' + str(uuid4())
            retained.write_text(correlation)
            status, row = self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})
            assert status == 202
        row = self.terminal(row)
        (ROOT / 'last-run.json').write_text(json.dumps(row))
        assert row['state'] == 'finished' and row['execution']['engine']['outcome'] == 'completed'
        self.record('installed-native-oci-handoff-completed', run_id=row['run_id'])

    def basic(self):
        self.wait_ready()
        assert self.control('/v1/contract', {'source': self.source}, token=False)[0] == 401
        self.record('private-ingress-authentication')
        previous = json.loads((ROOT / 'last-run.json').read_text())
        correlation = (ROOT / 'last-correlation').read_text()
        assert previous['state'] == 'finished' and previous['execution']['engine']['outcome'] == 'completed'
        status, replay = self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})
        assert status == 202 and replay == previous
        status, lookup = self.control('/v1/lookup', {'source': self.source, 'correlation_id': correlation})
        assert status == 200 and lookup['complete'] and lookup['runs'] == [previous]
        altered = copy.deepcopy(self.selection)
        altered['release']['closure_revision'] = '0' * 64
        assert self.control('/v1/admissions', {'source': self.source, 'selection': altered, 'correlation_id': correlation})[0] == 409
        self.record('completed-replay-and-altered-correlation', run_id=previous['run_id'])
        for mode, expected in [('stale', 'rejected'), ('unavailable', 'uncertain')]:
            self.fixture('reset')
            self.fixture(mode)
            _, row = self.admit('installed-' + mode)
            row = self.terminal(row)
            assert row['state'] == expected, row['state']
            assert 'container' not in row['execution'] and 'repository' not in row['execution']
            self.record('authority-' + mode + '-before-repository', run_id=row['run_id'])
        self.fixture('reset')
        self.fixture('lost-ack')
        correlation, row = self.admit('installed-lost-publication-ack')
        row = self.terminal(row)
        effects = {effect['kind']: effect for effect in row['effects']}
        assert effects['publish']['state'] == 'uncertain', effects['publish']['state']
        before = json.loads((ROOT / 'events.json').read_text())['publication_count']
        assert self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})[1] == row
        assert json.loads((ROOT / 'events.json').read_text())['publication_count'] == before
        self.record('lost-publication-ack-remains-fenced', run_id=row['run_id'])
        self.fixture('reset')
        for target in ('/etc/archon-confined/credentials/ingress', '/var/lib/archon-confined/journal.sqlite', '/run/archon-confined-docker/docker.sock'):
            result = subprocess.run(['runuser', '-u', 'nobody', '--', 'head', '-c', '1', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert result.returncode != 0
        self.record('unprivileged-state-credential-and-socket-denial')

    def crash(self):
        self.wait_ready()
        self.fixture('reset')
        self.fixture('hold')
        retained_owner = ROOT / 'crash-owner.json'
        if retained_owner.exists():
            retained = json.loads(retained_owner.read_text())
            correlation, owner = retained['correlation'], retained['owner']
            row = self.inspect(retained['run_id'])
        else:
            correlation, row = self.admit('installed-owner-death')
            for _ in range(90):
                row = self.inspect(row['run_id'])
                owner = row['execution'].get('container')
                if owner:
                    result = subprocess.run([*DOCKER, 'inspect', '--format', '{{.State.Running}}', owner['name']], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip() == 'true':
                        break
                time.sleep(1)
            else:
                raise RuntimeError('worker_not_started')
            (ROOT / 'crash-owner.json').write_text(json.dumps({'owner': owner, 'run_id': row['run_id'], 'correlation': correlation}))
        run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', 'archon-confined.service')
        self.wait_ready()
        retained = self.inspect(row['run_id'])
        assert retained['state'] == 'invoking' and retained['execution']['container'] == owner
        lookup = self.control('/v1/lookup', {'source': self.source, 'correlation_id': correlation})[1]
        assert len(lookup['runs']) == 1 and lookup['runs'][0] == retained
        self.record('admission-sigkill-retains-invocation-fence', run_id=row['run_id'])
        run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', 'archon-confined-cleanup.service')
        for _ in range(90):
            active = subprocess.run(['systemctl', 'is-active', '--quiet', 'archon-confined-cleanup.service']).returncode
            if active == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('cleanup_not_restarted')
        run('systemctl', 'start', 'archon-confined.service')
        self.wait_ready()
        assert self.inspect(row['run_id'])['state'] == 'invoking'
        self.record('independent-cleanup-sigkill-recovery')
        run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', 'archon-confined-containerd.service')
        run('systemctl', 'start', 'archon-confined-containerd.service', 'archon-confined-docker.service', 'archon-confined.service')
        self.wait_ready()
        assert self.inspect(row['run_id'])['state'] == 'invoking'
        self.enforcement()
        self.record('private-containerd-recovery-without-reinvocation')
        # Freeze only the dedicated daemon across expiry. The original daemon and
        # SSH remain available. Always resume even if an assertion fails.
        run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGSTOP', 'archon-confined-docker.service')
        try:
            while time.time() < owner['expires_at'] + 20:
                print('waiting for retained worker expiry', flush=True)
                time.sleep(min(30, max(1, owner['expires_at'] + 20 - time.time())))
        finally:
            run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGCONT', 'archon-confined-docker.service')
        for _ in range(90):
            result = subprocess.run([*DOCKER, 'inspect', owner['name']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if result.returncode != 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('expired_worker_not_removed')
        assert self.inspect(row['run_id'])['state'] == 'invoking'
        self.record('daemon-outage-across-expiry-cleanup-without-reinvocation')
        self.fixture('reset')


    def storage(self):
        self.wait_ready()
        self.fixture('reset')
        for label, target, owner, limit in [
            ('staging', '/tmp/archon-confined-runtime/work', 'archon-confined', 512 * 1024 ** 2),
            ('journal', '/var/lib/archon-confined', 'archon-confined', 2 * 1024 ** 3),
            ('daemon', '/var/lib/archon-confined-docker', 'root', 17 * 1024 ** 3),
        ]:
            directory = Path(target)
            fs = os.statvfs(directory)
            assert fs.f_blocks * fs.f_frsize <= limit
            filler = directory / 'conformance-capacity-fill'
            assert not filler.exists()
            program = """import errno,os,sys
path=sys.argv[1]
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
 for size in (1048576,4096,512,1):
  while True:
   try: os.write(fd,b'x'*size)
   except OSError as e:
    if e.errno != errno.ENOSPC: raise
    break
 os.fsync(fd)
finally: os.close(fd)
"""
            try:
                subprocess.run(['runuser', '-u', owner, '--', 'python3', '-c', program, str(filler)], check=True, timeout=600, stdout=subprocess.DEVNULL)
                correlation = 'installed-full-' + label + '-' + str(uuid4())
                status, row = self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})
                if label == 'journal':
                    assert status == 503, status
                else:
                    assert status == 202, status
                    row = self.terminal(row)
                    assert row['state'] in ({'rejected', 'uncertain'} if label == 'staging' else {'uncertain'}), row['state']
                assert json.loads((ROOT / 'events.json').read_text())['model_calls'] == 0
            finally:
                filler.unlink(missing_ok=True)
                os.sync()
            self.wait_ready()
            status, lookup = self.control('/v1/lookup', {'source': self.source, 'correlation_id': correlation})
            assert status == 200 and lookup['complete'] and len(lookup['runs']) <= 1
            if lookup['runs']:
                retained = lookup['runs'][0]
                assert self.control('/v1/admissions', {'source': self.source, 'selection': self.selection, 'correlation_id': correlation})[1] == retained
            self.record('bounded-' + label + '-exhaustion-without-reinvocation')
            self.fixture('reset')

    def configuration(self):
        self.wait_ready()
        for label, target in [('unit', Path('/etc/systemd/system/archon-confined.service')),
                              ('profile', Path('/etc/archon-confined/profile.json')),
                              ('runc-rule', Path('/etc/apparmor.d/local/runc'))]:
            original = target.read_bytes()
            run('systemctl', 'stop', 'archon-confined.service')
            try:
                if label in ('unit', 'runc-rule'):
                    target.write_bytes(original + b'\n# unreviewed drift\n')
                    if label == 'unit':
                        run('systemctl', 'daemon-reload')
                else:
                    value = json.loads(original)
                    value['allowed_paths'] = ['unapproved.py']
                    target.write_text(json.dumps(value))
                run('systemctl', 'start', 'archon-confined.service')
                time.sleep(5)
                result = subprocess.check_output(['systemctl', 'show', 'archon-confined.service', '-p', 'Result', '--value']).decode().strip()
                assert result == 'exit-code', result
                try:
                    self.control('/v1/contract', {'source': self.source})
                except (OSError, http.client.HTTPException):
                    pass
                else:
                    raise AssertionError('unreviewed configuration opened ingress')
            finally:
                run('systemctl', 'stop', 'archon-confined.service')
                target.write_bytes(original)
                run('systemctl', 'daemon-reload')
                run('systemctl', 'start', 'archon-confined.service')
            self.wait_ready()
            self.record('reject-installed-' + label + '-drift')

    def reboot_prepare(self):
        self.wait_ready()
        run('systemctl', 'stop', 'archon-confined.service')
        assert not subprocess.check_output([*DOCKER, 'ps', '-aq']).strip(), 'workers must be absent before reboot'
        run('systemctl', 'stop', 'archon-confined-cleanup.service')
        import sqlite3
        with sqlite3.connect('file:/var/lib/archon-confined/journal.sqlite?mode=ro', uri=True) as connection:
            before = {table: connection.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall() for table in
                      ('confined_admissions', 'confined_transitions', 'confined_run_facts', 'confined_effects', 'confined_effect_candidates')}
        (ROOT / 'before-reboot.json').write_text(json.dumps(before))
        enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', 'archon.service']).returncode == 0
        if not (ROOT / 'stock-was-enabled').exists():
            (ROOT / 'stock-was-enabled').write_text(str(enabled))
        run('systemctl', 'disable', 'archon.service')
        run('systemctl', 'enable', 'archon-confined.service', 'archon-confined-cleanup.service', 'archon-confined-docker.service', 'archon-confined-containerd.service', 'archon-conformance-fixtures.service')
        self.record('reboot-checkpoint-retained')

    def reboot_check(self):
        self.wait_ready()
        import sqlite3
        before = json.loads((ROOT / 'before-reboot.json').read_text())
        with sqlite3.connect('file:/var/lib/archon-confined/journal.sqlite?mode=ro', uri=True) as connection:
            after = {table: [list(row) for row in connection.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()] for table in before}
        assert before == after, 'reboot changed durable invocation/effect identity'
        assert subprocess.run(['systemctl', 'is-active', '--quiet', 'archon.service']).returncode != 0
        self.record('host-reboot-preserves-all-invocation-and-effect-records')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('enforcement', 'nominal', 'basic', 'crash', 'storage', 'configuration', 'reboot_prepare', 'reboot_check'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('test_host_root_required')
    checks = Checks()
    getattr(checks, args.mode)()


if __name__ == '__main__':
    main()
