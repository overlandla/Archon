"""Versioned child admission and observations; never a second ingress adapter.

Original allocations and run selections remain immutable. Scope/stop control is
retained separately; an uncertain execution is never put back on the queue.
"""
import hashlib
import json
import threading
from pathlib import Path

from .admission import Rejected
from .journal import AdmissionConflict, canonical


def member(selection):
    from archon_adapter.children import member as selected_member
    return selected_member(selection)


def binding(selection):
    from archon_adapter.children import binding as selected_binding
    return selected_binding(selection)


class Children:
    def __init__(self, runtime):
        self.runtime, self.journal = runtime, runtime.journal
        self.lock = threading.RLock()

    def initialize(self, run):
        with self.journal.connect() as connection:
            connection.execute('INSERT INTO confined_child_control(run_id) VALUES (?) ON CONFLICT DO NOTHING', (run,))

    def state(self, run):
        with self.journal.connect() as connection:
            value = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (run,)).fetchone()
            return dict(value) if value else None

    def handoff(self, run, original):
        state = self.state(run)
        if state and (state['blocked'] or state['stopped']):
            raise Rejected('stale_scope')
        if not state or not state['handoff']:
            return original
        current = json.loads(state['handoff'])
        references = {key: current[key] for key in original['references'] if key != 'instructions'}
        references['instructions'] = {'accepted_revision': current['instructions']['accepted_revision']}
        return {**original, 'references': references}

    def consumed(self, run, scope):
        with self.journal.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            state = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (run,)).fetchone()
            if state is None or state['stopped'] or state['blocked']:
                raise Rejected('stale_scope')
            if state['successor'] and json.loads(state['successor']) != scope:
                raise Rejected('stale_scope')
            connection.execute('UPDATE confined_child_control SET consumed=?, revision=revision+1 WHERE run_id=?', (canonical(scope), run))

    def validate_selection(self, selection):
        chosen = member(selection)
        allocation = selection['allocation']
        profile = self.runtime.profile
        source = allocation['source']
        if (source['deployment'].rstrip('/') != profile.authority.deployment or source['project_id'] != profile.authority.project
                or chosen['selection']['runtime_release'] != profile.release.selection()
                or chosen['mapping'] != profile.selected_repository
                or chosen['selection']['repository'] != {**profile.selected_repository, 'base': chosen['commit']}
                or chosen['parent_correlation_id'] != allocation['parent_correlation_id']):
            raise Rejected('unsupported')
        refs = chosen['selection']['references']['repositories']
        if (len(refs) != len(allocation['children']) or
                sorted(r['canonical_ref'] for r in refs) != sorted(c['canonical_ref'] for c in allocation['children'])):
            raise Rejected('unsupported')
        # Recompute deterministic child identities independently of caller IDs.
        from uuid import NAMESPACE_URL, uuid5
        for child in allocation['children']:
            original = canonical(['theseus-repository-allocation-v1', allocation['parent_correlation_id'], child['canonical_ref']])
            if child['child_id'] != str(uuid5(NAMESPACE_URL, original)) or child['correlation_id'] != hashlib.sha256(original.encode()).hexdigest():
                raise Rejected('unsupported')
        workspace = Path(chosen['workspace'])
        root = Path(profile.selected_repository['worktree_root'])
        repository = Path(profile.selected_repository['repository'])
        if workspace.is_relative_to(repository) or repository.is_relative_to(workspace):
            raise Rejected('unsupported')
        if workspace != root / chosen['child_id'] or not root.is_absolute() or root.resolve(strict=True) != root:
            raise Rejected('unsupported')
        if any(p.is_symlink() for p in (root, *root.parents)) or workspace.exists() or workspace.is_symlink():
            raise Rejected('unsupported')
        return chosen

    def reserve(self, run, selection):
        chosen = self.validate_selection(selection)
        workspace = Path(chosen['workspace'])
        # Called only after trusted current-authority validation. Never reuse an
        # occupied reservation, even if a foreign marker claims the right owner.
        import os
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in workspace.parent.parts[1:]:
                next_parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = next_parent
            # Check descriptor still denotes the configured canonical path before
            # mutation. Renaming an ancestor cannot redirect descriptor writes.
            if Path('/proc/self/fd/' + str(parent)).resolve() != workspace.parent:
                raise Rejected('unsupported')
            os.mkdir(workspace.name, 0o700, dir_fd=parent)
            child = os.open(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                owner = os.open('owner.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
                with os.fdopen(owner, 'w') as output:
                    output.write(canonical({'run_id': run, 'binding': binding(selection)}))
                    output.flush()
                    os.fsync(output.fileno())
                os.fsync(child)
            finally:
                os.close(child)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.journal.record_fact(run, 'child_workspace', {'workspace': str(workspace), 'binding': binding(selection)})

    def record(self, row):
        # One consistent projection, versioned whenever any exposed fact changes.
        # Effects and admission facts do not otherwise share a revision counter.
        with self.journal.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            current = connection.execute('SELECT * FROM confined_admissions WHERE run_id=?', (row['run_id'],)).fetchone()
            facts = {r['name']: json.loads(r['value']) for r in connection.execute('SELECT name,value FROM confined_run_facts WHERE run_id=?', (row['run_id'],))}
            state = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (row['run_id'],)).fetchone()
            effects = [{**dict(r), 'receipt': json.loads(r['response']) if r['response'] else None} for r in connection.execute('SELECT kind,state,response FROM confined_effects WHERE run_id=? ORDER BY kind,operation_id', (row['run_id'],))]
            value = self.project(current, facts, state, effects)
            retained = connection.execute('SELECT revision,value FROM confined_child_observations WHERE run_id=?', (row['run_id'],)).fetchone()
            encoded = canonical(value)
            revision = 0 if retained is None else retained['revision'] + (retained['value'] != encoded)
            connection.execute('INSERT INTO confined_child_observations VALUES (?,?,?) ON CONFLICT(run_id) DO UPDATE SET revision=excluded.revision,value=excluded.value', (row['run_id'], revision, encoded))
            return {**value, 'revision': revision}

    def project(self, row, facts, state, effects):
        current = row
        selection = json.loads(row['selection'])['child']
        handoff = json.loads(state['handoff']) if state and state['handoff'] else member(selection)['selection']['references']
        scope = handoff['scope']['selected']
        outcome = {'admitted': 'admitted', 'checking': 'admitted', 'invoking': 'active', 'uncertain': 'uncertain', 'rejected': 'rejected', 'finished': 'failed'}[current['state']]
        if current['state'] == 'finished':
            outcome = {'completed': 'succeeded', 'failed': 'failed', 'paused': 'blocked'}.get(facts.get('engine', {}).get('outcome'), 'uncertain')
        if outcome == 'succeeded' and any(e.get('state') != 'acknowledged' for e in effects):
            outcome = 'uncertain'
        if state and state['blocked'] and outcome not in {'succeeded', 'failed', 'rejected'}:
            outcome = 'blocked'
        if state and state['stopped'] == 2 and outcome not in {'succeeded', 'failed', 'rejected'}:
            outcome = 'cancelled'
        chosen = member(selection)
        repository = next(r for r in chosen['selection']['references']['repositories'] if r['canonical_ref'] == chosen['canonical_ref'])
        artifacts = []
        for effect in effects:
            if effect['kind'] == 'publish' and effect['state'] == 'acknowledged':
                receipt = effect['receipt']
                if receipt['repository_id'] != self.runtime.profile.repository_id:
                    raise AdmissionConflict('foreign_child_publication')
                artifacts.append({'repository_id': repository['id'], 'revision': receipt['commit'],
                                  'artifact_type': 'pull-request', 'artifact_ref': receipt['url'], 'digest': receipt['export_id']})
        return {'binding': binding(selection), 'run_id': row['run_id'],
                'state': outcome, 'scope': scope, 'artifacts': artifacts, 'diagnostic': current['diagnostic']}

    def bound_run(self, intent):
        row = self.runtime._row(intent['run_id'])
        selection = json.loads(row['selection'])
        if 'child' not in selection or binding(selection['child']) != intent['binding']:
            raise AdmissionConflict('foreign_child_control')
        return row

    def notify(self, intent):
        row = self.bound_run(intent)
        self.initialize(row['run_id'])
        with self.lock, self.journal.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            old = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (row['run_id'],)).fetchone()
            if old['successor']:
                from archon_adapter.progress_repository import revision
                if revision(json.loads(old['successor'])) > revision(intent['successor']):
                    raise AdmissionConflict('obsolete_child_notice')
                if revision(json.loads(old['successor'])) == revision(intent['successor']) and old['notice'] != canonical(intent):
                    raise AdmissionConflict('child_notice_conflict')
            if old['notice'] == canonical(intent) and old['notice_ack']:
                return {'intent': intent, 'blocked': True}
            if old['notice'] != canonical(intent):
                connection.execute('UPDATE confined_child_control SET blocked=1, notice_ack=0, successor=?, notice=?, decision=NULL, consumed=NULL, revision=revision+1 WHERE run_id=?',
                               (canonical(intent['successor']), canonical(intent), row['run_id']))
        drained = self.drain(row['run_id'])
        if drained:
            with self.journal.connect() as connection:
                connection.execute('UPDATE confined_child_control SET notice_ack=1 WHERE run_id=? AND notice=?', (row['run_id'], canonical(intent)))
        return {'intent': intent, 'blocked': drained}

    def reconcile(self, intent):
        row = self.bound_run(intent['notice'])
        state = self.state(row['run_id'])
        if state is None or state['notice'] != canonical(intent['notice']) or state['stopped'] or not state['notice_ack']:
            raise AdmissionConflict('child_reconciliation_conflict')
        if state['decision'] and state['decision'] != canonical(intent):
            raise AdmissionConflict('child_decision_conflict')
        if state['decision'] == canonical(intent) and state['consumed'] == canonical(intent['notice']['successor']):
            return {'intent': intent, 'consumed': True}
        # A running provider cannot be relabeled under new scope. Only a queued
        # worker can consume a replacement initial context; other states remain
        # blocked and require separately admitted work, never another invocation.
        if row['state'] != 'admitted':
            return {'intent': intent, 'consumed': False}
        original = json.loads(row['selection'])['handoff']
        current = intent['handoff']
        refs = {key: current[key] for key in original['references'] if key != 'instructions'}
        refs['instructions'] = {'accepted_revision': current['instructions']['accepted_revision']}
        if any(refs[key] != original['references'][key] for key in ('source','task','work_unit','repositories')) or refs['scope']['selected'] != intent['notice']['successor']:
            raise Rejected('unsupported')
        self.runtime.profile.authority.check({**original, 'references': refs})
        with self.lock, self.journal.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            latest = connection.execute('SELECT state FROM confined_admissions WHERE run_id=?', (row['run_id'],)).fetchone()
            control = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (row['run_id'],)).fetchone()
            if latest['state'] != 'admitted' or control['notice'] != canonical(intent['notice']) or control['stopped']:
                raise AdmissionConflict('child_reconciliation_changed')
            connection.execute('UPDATE confined_child_control SET handoff=?, decision=?, blocked=0, revision=revision+1 WHERE run_id=?',
                               (canonical(current), canonical(intent), row['run_id']))
        return {'intent': intent, 'consumed': False}

    def stop(self, intent):
        row = self.bound_run(intent)
        self.initialize(row['run_id'])
        with self.lock, self.journal.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            state = connection.execute('SELECT * FROM confined_child_control WHERE run_id=?', (row['run_id'],)).fetchone()
            if state['stop_intent'] and state['stop_intent'] != canonical(intent):
                raise AdmissionConflict('child_stop_conflict')
            if state['stopped'] == 2:
                return {'intent': intent, 'stopped': True}
            connection.execute('UPDATE confined_child_control SET stopped=1, blocked=1, stop_intent=?, revision=revision+1 WHERE run_id=?', (canonical(intent), row['run_id']))
        if not self.drain(row['run_id']):
            return {'intent': intent, 'stopped': False}
        with self.journal.connect() as connection:
            connection.execute('UPDATE confined_child_control SET stopped=2, revision=revision+1 WHERE run_id=?', (row['run_id'],))
        return {'intent': intent, 'stopped': True}

    def drain(self, run):
        # A DB fence prevents new dequeue/effects; only a queued run or a
        # drained owner proves its already-running descendants have stopped.
        latest, facts = self.journal.inspect_run(run)
        if latest['state'] in {'admitted', 'finished', 'rejected'}:
            return True
        pending = self.runtime.pending.get(run)
        if pending is None:
            return False
        server = pending.get('actions')
        if server:
            server.seal_and_drain()
        if 'container' in facts:
            from .watchdog import remove_owned
            if not remove_owned(facts['container']['name'], facts['container']['image']):
                return False
        return pending['finished'].wait(10)


class ObservationSink:
    def __init__(self, journal, run, check):
        self.journal, self.run, self.check = journal, run, check

    def report(self, operation_id, value):
        if set(value) != {'progress'} or value['progress'] not in ('not-started','in-progress','blocked','complete'):
            raise ValueError('unsupported_progress')
        self.check()
        receipt = {'run_id': self.run, 'operation_id': operation_id, 'progress': value['progress']}
        self.journal.record_fact(self.run, 'child_progress:' + operation_id, receipt)
        return receipt

    def validate_receipt(self, operation_id, request, response):
        if response != {'run_id': self.run, 'operation_id': operation_id, 'progress': request['progress']}:
            raise ValueError('child_progress_receipt_mismatch')
