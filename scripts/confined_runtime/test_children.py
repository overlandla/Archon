"""Child control invariants on the real durable runtime journal."""
import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from .admission import Rejected
from .children import Children, binding
from .journal import AdmissionConflict, Journal
from .lifecycle import Lifecycle


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = Journal(self.root / 'journal.sqlite')
        self.runtime = SimpleNamespace(journal=self.journal, pending={}, profile=SimpleNamespace(repository_id=42))
        self.children = Children(self.runtime)
        self.runtime._row = lambda run: self.journal.inspect_run(run)[0]
        self.scope = {'kind':'scope_revision', 'identity':str(uuid4()), 'path':'/api/projects/1000/tasks/42/scope-revisions/2'}
        self.child_id = str(uuid4())
        self.selection = {'format':'theseus-child-execution-v1', 'child_id':self.child_id, 'allocation':{
            'format':'theseus-repository-allocation-v1', 'source':{'deployment':'https://theseus.example.test','project_id':1000},
            'admission_id':str(uuid4()), 'children':[{'child_id':self.child_id, 'correlation_id':'child-correlation', 'canonical_ref':'github:overlandla/theseus',
            'selection':{'references':{'scope':{'selected':self.scope}, 'repositories':[{'id':str(uuid4()),'canonical_ref':'github:overlandla/theseus'}]}}}]}}
        self.row = self.journal.admit('https://theseus.example.test',1000,'child-correlation',{'child':self.selection})
        self.run = self.row['run_id']
        self.intent = {'id':str(uuid4()), 'run_id':self.run, 'binding':binding(self.selection)}

    def invoking(self):
        self.row = self.journal.transition(self.run,0,'check')
        self.row = self.journal.transition(self.run,1,'invoke')

    def test_child_admission_control_is_atomic_and_additive(self):
        self.assertIsNotNone(self.children.state(self.run))
        before = self.journal.inspect_run(self.run)
        restarted = Journal(self.journal.path)
        self.assertEqual(before, restarted.inspect_run(self.run))
        self.assertEqual(self.row, restarted.admit('https://theseus.example.test',1000,'child-correlation',{'child':self.selection}))

    def test_effect_projection_has_durable_monotone_observation_version(self):
        self.invoking()
        before = self.children.record(self.row)
        self.journal.begin_effect(self.run,'publish','publish',{'export_id':'a'*64})
        self.journal.finish_effect(self.run,'publish','publish','acknowledged',{'repository_id':42,'commit':'b'*40,'url':'https://github.com/overlandla/theseus/pull/1','export_id':'a'*64})
        after = self.children.record(self.row)
        self.assertGreater(after['revision'],before['revision'])
        self.assertEqual(len(after['artifacts']),1)
        self.assertEqual(after,self.children.record(self.row))
        self.assertEqual(after,Children(self.runtime).record(self.row))

    def test_stop_queued_fences_late_dequeue(self):
        self.assertTrue(self.children.stop(self.intent)['stopped'])
        with self.assertRaises(AdmissionConflict):
            self.journal.transition(self.run,0,'check')
        self.assertEqual(self.children.record(self.row)['state'],'cancelled')
        self.assertTrue(self.children.stop(self.intent)['stopped'])

    def test_interrupted_owner_cannot_confirm_stop(self):
        self.invoking()
        self.assertFalse(self.children.stop(self.intent)['stopped'])
        with self.assertRaises(AdmissionConflict):
            self.journal.begin_effect(self.run,'export','new',{})
        with self.assertRaises(AdmissionConflict):
            self.journal.transition(self.run,2,'finish')

    def test_scope_notice_cannot_confirm_block_for_unknown_owner(self):
        self.invoking()
        intent = {**self.intent,'successor':{**self.scope,'path':'/api/projects/1000/tasks/42/scope-revisions/3'}}
        self.assertFalse(self.children.notify(intent)['blocked'])
        with self.assertRaises(AdmissionConflict):
            self.children.reconcile({'notice':intent, 'handoff':{}})
        with self.assertRaises(Rejected):
            self.children.consumed(self.run,self.scope)

    def test_late_stop_preserves_completed_outcome(self):
        self.invoking()
        self.journal.record_fact(self.run,'engine',{'outcome':'completed'})
        self.row = self.journal.transition(self.run,2,'finish')
        self.assertEqual(self.children.record(self.row)['state'],'succeeded')
        self.children.stop(self.intent)
        self.assertEqual(self.children.record(self.row)['state'],'succeeded')

    def test_foreign_child_intent_is_rejected(self):
        foreign = copy.deepcopy(self.intent)
        foreign['binding']['child'] = str(uuid4())
        with self.assertRaises(AdmissionConflict):
            self.children.stop(foreign)
        self.assertEqual(self.children.state(self.run)['stopped'],0)

    def test_scope_receipt_requires_positive_consumption_acknowledgement(self):
        channel = Lifecycle(self.root/'lifecycle.sock',self.run,timeout=2,consume=lambda scope:self.children.consumed(self.run,scope))
        self.addCleanup(channel.close)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(str(channel.path))
            self.assertEqual(client.recv(6),b'ready\n')
            client.sendall(json.dumps({'run_id':self.run,'scope':self.scope}).encode()+b'\n')
            self.assertEqual(client.recv(9),b'consumed\n')
            client.sendall(json.dumps({'run_id':self.run,'state':'completed'}).encode())
        self.assertEqual(channel.await_outcome(),'completed')

    def test_denied_scope_receipt_never_grants_permission(self):
        self.children.stop(self.intent)
        channel = Lifecycle(self.root/'lifecycle.sock',self.run,timeout=2,consume=lambda scope:self.children.consumed(self.run,scope))
        self.addCleanup(channel.close)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(str(channel.path))
            self.assertEqual(client.recv(6),b'ready\n')
            client.sendall(json.dumps({'run_id':self.run,'scope':self.scope}).encode()+b'\n')
            self.assertEqual(client.recv(9),b'')
        with self.assertRaises(RuntimeError):
            channel.await_outcome()

    def test_drained_owner_fact_survives_restart_without_false_unknown_stop(self):
        self.invoking()
        self.journal.transition(self.run,2,'uncertain')
        self.journal.record_fact(self.run,'owner_drained',{'drained':True})
        restarted = Children(self.runtime)
        self.assertTrue(restarted.stop(self.intent)['stopped'])
        self.assertEqual(restarted.record(self.row)['state'],'cancelled')

    def test_concurrent_reconciliation_cannot_replace_retained_decision(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        references = {'source':self.selection['allocation']['source'], 'task':{}, 'work_unit':{}, 'repositories':[],
                      'scope':{'selected':self.scope}, 'instructions':{'accepted_revision':str(uuid4())}}
        original = {'references':references}
        row = self.journal.admit('https://theseus.example.test',1000,'concurrent-decision',{'child':self.selection,'handoff':original})
        run = row['run_id']
        notice = {**self.intent,'run_id':run,'successor':{**self.scope,'path':'/api/projects/1000/tasks/42/scope-revisions/3'}}
        self.assertTrue(self.children.notify(notice)['blocked'])
        current = {**references,'scope':{'selected':notice['successor']}}
        barrier = Barrier(2)
        self.runtime.profile.authority = SimpleNamespace(check=lambda selection:barrier.wait(timeout=3))
        intents = [{'id':str(uuid4()),'notice':notice,'handoff':current} for _ in range(2)]
        def reconcile(intent):
            try:
                return self.children.reconcile(intent)
            except AdmissionConflict as error:
                return error
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reconcile,intents))
        self.assertEqual(sum(isinstance(r,AdmissionConflict) for r in results),1)
        accepted = next(r['intent'] for r in results if isinstance(r,dict))
        self.assertEqual(json.loads(self.children.state(run)['decision']),accepted)
        # Replaying the acknowledged notice after reconciliation is historical;
        # it must not drain or reblock the worker consuming that successor.
        self.journal.transition(run,0,'check')
        self.journal.transition(run,1,'invoke')
        self.assertTrue(self.children.notify(notice)['blocked'])
        self.assertFalse(self.children.state(run)['blocked'])
