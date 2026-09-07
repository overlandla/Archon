"""Reproduce the bounded #778 matrix without operator credentials or live writes.

The output records controlled behavior, not a supported deployment attestation or
Theseus verification disposition. Installing an approved profile belongs to #531.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from .policy_identity import revision


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    base = [sys.executable, '-m', 'scripts.confined_runtime.']
    common = ['--image', args.image, '--worker', str(args.worker.resolve())]
    cases = [('components', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/confined_runtime', '-t', '.', '-p', 'test_*.py', '-q'])]
    for name, module, extra in [
        ('confinement', 'oci_conformance', []),
        ('engine-death', 'oci_conformance', ['--interrupt-engine']),
        ('actions', 'action_conformance', []),
        ('publication-ack-loss', 'action_conformance', ['--lost-ack']),
        ('git-fetch', 'git_conformance', []),
        ('supervisor-death', 'watchdog_conformance', []),
    ]:
        cases.append((name, base[:-1] + [base[-1] + module] + common + extra))
    for case in ['current', 'lost-publication-ack', 'stale-scope', 'stale-guidance', 'unavailable-authority',
                 'changed-mode', 'bootstrap-stale-scope', 'bootstrap-stale-guidance', 'broker-start-failure']:
        cases.append(('runtime-' + case, base[:-1] + [base[-1] + 'runtime_conformance'] + common + ['--native', str(args.native.resolve()), '--case', case]))
    identity = revision()
    results = []
    for name, command in cases:
        with (args.output / (name + '.log')).open('xb') as log:
            try:
                result = subprocess.run(command, cwd=Path(__file__).resolve().parents[2], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=600)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        results.append({'case': name, 'exit_code': code, 'passed': code == 0})
        print(json.dumps(results[-1]), flush=True)
    unchanged = revision() == identity
    report = {'format': 'archon-controlled-matrix-v1', 'image': args.image,
              'worker_revision': hashlib.sha256(args.worker.read_bytes()).hexdigest(),
              'provider_revision': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'policy_revision': identity, 'policy_unchanged': unchanged,
              'controlled_matrix_passed': unchanged and all(row['passed'] for row in results),
              'full_runtime_conformance': False, 'live_acceptance': False,
              'release_attestation': None, 'cases': results}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['controlled_matrix_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
