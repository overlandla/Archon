"""Opt-in installed-service fixtures on an explicitly authorized test host.

Real service code, HTTPS, Git, Archon, native provider and OCI execution; only
external replies are synthetic. Never run this helper on a shared/live host.
It is not imported by the production entry and grants no release approval.
"""
import argparse
import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
import secrets
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

ROOT = Path('/var/lib/archon-conformance')
RELEASE = Path('/opt/archon-confined/release')
IMAGE = 'sha256:1b6a4c7356815e450b1bf36a175cc071d3c076b294028727de8cf6e25eef6c78'
NAMES = ('theseus.example.test', 'model.example.test', 'api.github.com', 'github.com')


def fixtures():
    # The production wheel deliberately omits test support. Only this separate
    # fixture process explicitly loads its retained source copy.
    spec = importlib.util.spec_from_file_location('archon_adapter.test_support', ROOT / 'test_support.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from .conformance import SyntheticModel
    from .git_conformance import SyntheticGit
    from .runtime_conformance import GitHubFixture, SourceFixture
    return module.handoff_exchange, SourceFixture, GitHubFixture, SyntheticGit, SyntheticModel


def command(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=120, **kwargs)


def prepare(worker):
    import certifi

    from .admission import Release
    from .policy_identity import revision
    from .runtime import NATIVE_CONFIG, Profile
    from .source_authority import TheseusAuthority
    handoff, _, _, SyntheticGit, _ = fixtures()
    if (ROOT / 'selection.json').exists() or Path('/etc/archon-confined/profile.json').exists():
        raise RuntimeError('refusing_to_replace_profile_or_fixture')
    config = Path('/etc/archon-confined')
    (config / 'credentials').mkdir(parents=True, mode=0o700)
    config.chmod(0o755)
    for name in ('ingress', 'theseus', 'github', 'model'):
        target = config / 'credentials' / name
        target.write_text(secrets.token_urlsafe(36))
        target.chmod(0o600)
    secret = {p.name: p.read_text() for p in (config / 'credentials').iterdir()}
    authoring = ROOT / 'authoring'
    workflow = authoring / '.archon/workflows/theseus-implementation.yaml'
    workflow.parent.mkdir(parents=True)
    workflow.write_text('name: theseus-implementation\ndescription: Installed controlled fixture\nnodes:\n'
        '  - id: implement\n    provider: codex\n    model: fixture-model\n    prompt: Execute the controlled task.\n'
        '  - id: verify\n    depends_on: [implement]\n    bash: test -f src/implementation.py\n')
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(ROOT), 'ARCHON_HOME': str(ROOT / 'build-state'),
                   'DATABASE_URL': '', 'LOG_LEVEL': 'error', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    initial, prepared = ROOT / 'initial.json', ROOT / 'prepared.json'
    initial.write_text(json.dumps({'runId': str(uuid4()), 'cwd': '/workspace/repository', 'sourceRoot': str(authoring),
        'workflowIdentity': 'theseus-implementation', 'model': 'fixture-model', 'codexBinary': '/runtime/codex'}))
    command(str(worker), 'prepare', str(initial), str(prepared), env=environment, stdout=subprocess.DEVNULL)
    capture = json.loads(prepared.read_text())
    shutil.copytree(capture['captureRoot'], RELEASE / 'capture')
    for path in [RELEASE / 'capture', *(RELEASE / 'capture').rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    repository = ROOT / 'repository'
    repository.mkdir()
    command('git', 'init', '-q', str(repository), env=environment)
    (repository / 'README.md').write_text('Synthetic installed-host base.\n')
    git = SyntheticGit(repository)
    (ROOT / 'base.json').write_text(json.dumps({'commit': git.commit}))
    exchange = handoff()
    (ROOT / 'exchange.json').write_text(json.dumps(exchange))
    # Stop the old integration before routing any public API hostname to a local
    # fixture. No old credentials are loaded or copied by this harness.
    status = subprocess.run(['systemctl', 'is-active', '--quiet', 'archon.service']).returncode
    (ROOT / 'stock-was-active').write_text(str(status == 0))
    if status == 0:
        command('systemctl', 'stop', 'archon.service')
    shutil.copyfile('/etc/hosts', ROOT / 'hosts.before')
    with Path('/etc/hosts').open('a') as stream:
        stream.write('\n127.0.0.1 ' + ' '.join(NAMES) + ' # archon-conformance\n')
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '7',
        '-keyout', str(ROOT / 'fixture.key'), '-out', str(ROOT / 'fixture.crt'), '-subj', '/CN=Archon conformance only',
        '-addext', 'subjectAltName=' + ','.join('DNS:' + name for name in NAMES),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (ROOT / 'fixture.key').chmod(0o600)
    shutil.copyfile(ROOT / 'fixture.crt', '/usr/local/share/ca-certificates/archon-conformance.crt')
    Path('/usr/local/share/ca-certificates/archon-conformance.crt').chmod(0o644)
    command('update-ca-certificates', stdout=subprocess.DEVNULL)
    ca = Path(certifi.where())
    shutil.copyfile(ca, ROOT / 'certifi.before')
    with ca.open('ab') as stream:
        stream.write(b'\n' + (ROOT / 'fixture.crt').read_bytes())
    selected = {'canonical_ref': 'github:overlandla/theseus', 'repository': '/approved/repo', 'worktree_root': '/approved/worktrees', 'base': 'main'}
    release = Release('theseus-implementation', capture['executableRevision'], hashlib.sha256(worker.read_bytes()).hexdigest(),
        'bbc3341e44c9ead340ed9570c17be936e37870f570751a941699ffd04d672827', IMAGE.removeprefix('sha256:'), revision(),
        hashlib.sha256(NATIVE_CONFIG.encode()).hexdigest(), '0' * 64)
    profile = Profile(release, IMAGE, RELEASE / 'capture', 'fixture-model', TheseusAuthority('https://theseus.example.test', 1000, secret['theseus']),
        selected, 'overlandla', 'theseus', 42, frozenset({'src/implementation.py'}), 'operator-isolated-actions-disabled',
        secret['github'], 'https://model.example.test', secret['model'])
    release = replace(release, authority_configuration_revision=profile.configuration_revision())
    public = {'format': 'archon-operator-profile-v1', 'release': release.selection(), 'port': 8788,
        'source': {'deployment': profile.authority.deployment, 'project': 1000}, 'allowed_paths': sorted(profile.allowed_paths),
        **{key: getattr(profile, key) for key in ('model', 'model_origin', 'selected_repository', 'owner', 'repository', 'repository_id', 'automation_mode')}}
    (config / 'profile.json').write_text(json.dumps(public, indent=2) + '\n')
    (config / 'profile.json').chmod(0o644)
    refs = {key: copy.deepcopy(exchange[key]) for key in ('schema_version', 'exchange_type', 'source', 'task', 'work_unit_graph', 'work_unit', 'scope', 'sources', 'dependencies', 'repositories', 'authority')}
    refs['instructions'] = {'accepted_revision': exchange['instructions']['accepted_revision']}
    selection = {'release': release.selection(), 'source': public['source'], 'handoff': {
        'workflow_identity': release.identity, 'workflow_revision': release.closure_revision, 'workflow_revision_format': 'archon-immutable-closure-v1',
        'runtime_release': release.selection(), 'repository': selected, 'references': refs}}
    (ROOT / 'selection.json').write_text(json.dumps(selection))
    print('synthetic_profile_prepared')


TOOL = r'''import base64,hashlib,http.client,json,socket,os
from pathlib import Path
assert os.getuid()==65532
assert not Path('/run/docker.sock').exists()
assert not Path('/etc/archon-confined/credentials').exists()
assert not Path('/var/lib/archon-confined/journal.sqlite').exists()
assert Path('/sys/fs/cgroup/memory.max').read_text().strip()=='1073741824'
assert Path('/sys/fs/cgroup/pids.max').read_text().strip()=='128'
def action(kind,request):
 c=http.client.HTTPConnection('localhost',timeout=30); c.sock=socket.socket(socket.AF_UNIX); c.sock.connect('/broker/actions.sock')
 c.request('POST','/actions',json.dumps({'kind':kind,'operation_id':kind,'request':request}),{'Content-Type':'application/json'})
 r=c.getresponse(); result=(r.status,json.loads(r.read())); c.close(); return result
content=b'answer = 42\n'
Path('src').mkdir(exist_ok=True); Path('src/implementation.py').write_bytes(content)
status,export=action('export',{'files':[{'path':'src/implementation.py','size':len(content),'sha256':hashlib.sha256(content).hexdigest(),'content':base64.b64encode(content).decode(),'executable':False}],'deletions':[]})
assert status==200
assert action('publish',export)[0]==200
assert action('progress',{'progress':'complete'})[0]==200
for kind in ['merge','approve','deploy','secret','verification','release']:
 assert action(kind,{})[0]==403
'''


def serve():
    import httpx
    _, SourceFixture, GitHubFixture, SyntheticGit, SyntheticModel = fixtures()
    exchange = json.loads((ROOT / 'exchange.json').read_text())
    events = []
    git = SyntheticGit.__new__(SyntheticGit)
    git.repository, git.requests = ROOT / 'repository', []
    git.env = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    git.commit = json.loads((ROOT / 'base.json').read_text())['commit']
    source = SourceFixture(exchange, events)
    github = GitHubFixture(git.repository, git, events, exchange, False)
    model = SyntheticModel('python3 -c ' + shlex.quote(TOOL))
    secret = {p.name: p.read_text() for p in Path('/etc/archon-confined/credentials').iterdir()}
    lock = threading.Lock()
    model_ready = threading.Event()
    model_ready.set()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.dispatch()
        def do_POST(self):
            self.dispatch()
        def dispatch(self):
            if self.headers.get('Host', '').split(':')[0] == 'model.example.test' and self.headers.get('Authorization') == 'Bearer ' + secret['model']:
                model_ready.wait(90)
            with lock:
                try:
                    host = self.headers.get('Host', '').split(':')[0]
                    key = 'github' if host in ('api.github.com', 'github.com') else 'model' if host == 'model.example.test' else 'theseus'
                    expected = ('Basic ' + base64.b64encode(('x-access-token:' + secret[key]).encode()).decode()) if host == 'github.com' else 'Bearer ' + secret[key]
                    if host not in NAMES or self.headers.get('Authorization') != expected:
                        self.send_error(401)
                        return
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 <= length <= 8 * 1024 * 1024:
                        self.send_error(413)
                        return
                    body = self.rfile.read(length)
                    content_type = 'application/json'
                    if self.path.startswith('/fixture/'):
                        if self.command != 'POST' or host != 'theseus.example.test':
                            self.send_error(403)
                            return
                        mode = json.loads(body)['mode']
                        if mode == 'reset':
                            source.exchange = copy.deepcopy(exchange)
                            source.failure = False
                            model.calls = 0
                            model_ready.set()
                            github.lost_ack = False
                            events.clear()
                        elif mode == 'stale':
                            source.exchange['scope']['selected']['identity'] = str(uuid4())
                        elif mode == 'unavailable':
                            source.failure = True
                        elif mode == 'hold':
                            model_ready.clear()
                        elif mode == 'lost-ack':
                            github.lost_ack = True
                        else:
                            raise ValueError('unknown_fixture_mode')
                        status, data = 200, b'{}'
                    elif host == 'github.com':
                        data = git.send(self.command, self.path.removeprefix('/overlandla/theseus.git'), body)
                        status, content_type = 200, 'application/x-git-upload-pack-result'
                    elif host == 'api.github.com' or self.command == 'POST':
                        if host == 'model.example.test':
                            status, data = model.send(body)
                            content_type = 'text/event-stream'
                        else:
                            data = json.dumps(github(self.command, self.path, json.loads(body) if body else None)).encode()
                            status = 200
                    else:
                        reply = source.handle(httpx.Request(self.command, 'https://' + host + self.path))
                        status, data = reply.status_code, reply.content
                    (ROOT / 'events.json').write_text(json.dumps({'events': events, 'model_calls': model.calls, 'publication_count': len(github.pulls)}))
                    self.send_response(status)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except Exception:
                    self.send_error(503)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / 'fixture.crt', ROOT / 'fixture.key')
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def restore():
    """Drain test services and remove only the exact synthetic network inputs."""
    import certifi

    command('systemctl', 'stop', 'archon-confined.service')
    docker = ['docker', '--host', 'unix:///run/archon-confined-docker/docker.sock']
    if subprocess.check_output([*docker, 'ps', '-aq']).strip():
        raise RuntimeError('wait_for_owned_container_cleanup_before_restore')
    hosts = Path('/etc/hosts')
    original = (ROOT / 'hosts.before').read_bytes()
    added = ('\n127.0.0.1 ' + ' '.join(NAMES) + ' # archon-conformance\n').encode()
    ca = Path('/usr/local/share/ca-certificates/archon-conformance.crt')
    bundle = Path(certifi.where())
    certificate = (ROOT / 'fixture.crt').read_bytes()
    before_bundle = (ROOT / 'certifi.before').read_bytes()
    if hosts.read_bytes() != original + added or ca.read_bytes() != certificate or bundle.read_bytes() != before_bundle + b'\n' + certificate:
        raise RuntimeError('network_inputs_changed_preserve_for_operator')
    for unit in ('archon-confined-cleanup.service', 'archon-confined-docker.service', 'archon-confined-containerd.service', 'archon-conformance-fixtures.service'):
        command('systemctl', 'stop', unit)
    command('systemctl', 'disable', 'archon-confined.service', 'archon-confined-cleanup.service',
            'archon-confined-docker.service', 'archon-confined-containerd.service', 'archon-conformance-fixtures.service')
    hosts.write_bytes(original)
    ca.unlink()
    command('update-ca-certificates', stdout=subprocess.DEVNULL)
    bundle.write_bytes(before_bundle)
    enabled = ROOT / 'stock-was-enabled'
    if enabled.exists() and enabled.read_text() == 'True':
        command('systemctl', 'enable', 'archon.service')
    if (ROOT / 'stock-was-active').read_text() == 'True':
        command('systemctl', 'start', 'archon.service')
    print('synthetic_network_removed_original_service_restored')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'serve', 'restore'))
    parser.add_argument('--worker', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not ROOT.is_dir():
        raise SystemExit('dedicated_test_host_root_required')
    os.umask(0o077)
    if args.mode == 'prepare':
        prepare(args.worker)
    elif args.mode == 'serve':
        serve()
    else:
        restore()


if __name__ == '__main__':
    main()
