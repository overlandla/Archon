import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from .admission import Rejected, Release
from .journal import Journal
from .runtime import NATIVE_CONFIG, Profile, Runtime
from .source_authority import TheseusAuthority


class ProfileTests(unittest.TestCase):
    def test_policy_profile_and_repository_are_bound_before_source_staging(self):
        with tempfile.TemporaryDirectory() as directory, patch('scripts.confined_runtime.runtime.policy_revision', return_value='a' * 64):
            release = Release('proof', *('a' * 64 for _ in range(7)))
            release = replace(release, native_configuration_revision=hashlib.sha256(NATIVE_CONFIG.encode()).hexdigest())
            profile = Profile(release, 'sha256:' + 'a' * 64, Path(directory), 'fixture-model',
                TheseusAuthority('https://source.invalid', 1000, 'synthetic'),
                {'canonical_ref': 'github:owner/repo', 'repository': '/approved/repo', 'worktree_root': '/approved/worktrees', 'base': 'main'},
                'owner', 'repo', 1, frozenset({'src/main.py'}), 'operator-isolated-actions-disabled',
                'synthetic', 'https://model.invalid', 'synthetic')
            profile = replace(profile, release=replace(release, authority_configuration_revision=profile.configuration_revision()))
            profile.validate()
            runtime = Runtime(Journal(Path(directory) / "state.sqlite"), profile)
            profile.selected_repository['base'] = 'mutated'
            self.assertEqual(runtime.profile.selected_repository['base'], 'main')
            for change in ({'model': 'other'}, {'allowed_paths': frozenset({'deploy.sh'})}, {'repository_id': 2},
                           {'release': replace(runtime.profile.release, policy_revision='b' * 64)}):
                with self.subTest(change=change), self.assertRaises(Rejected):
                    replace(runtime.profile, **change).validate()
            foreign = replace(runtime.profile, owner='foreign')
            foreign = replace(foreign, release=replace(foreign.release, authority_configuration_revision=foreign.configuration_revision()))
            with self.assertRaises(Rejected):
                foreign.validate()
