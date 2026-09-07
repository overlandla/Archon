# Experimental confined worker — Theseus #778

This is a **draft source experiment, not a supported runtime release**. Do not
install it over the configured Archon service, expose a launch endpoint, use
operator credentials, or enable the Theseus connector with it.

The source base is Archon v0.10.0,
`c8f439a0269fee0f33f2f9f64752d66860112274`, matching the installed compiled
runtime inspected on LXC 121. The older `/opt/archon` source directory is not the
revision of that installed binary. These changes use an isolated development
branch; the existing GitHub, Codex and Telegram integration is unchanged.

## What is implemented

- A private engine entry prepares and checks the actual complete captured source,
  rejects a narrow set of unsupported workflow shapes and settings, and consumes
  that final capture under a read-only mount. It uses invocation-scoped in-memory
  SQLite so generated processes cannot rewrite the engine's control database.
- Descriptor-relative source staging rejects links, special files, oversize or
  incomplete reads. The engine entry also rejects ambient home authoring scopes.
- A Linux x86-64 bubblewrap/seccomp experiment encloses the engine, native Codex,
  model tools and shell test nodes. It supplies private writable repository/state
  roots, no operator home or credentials, no host network, and a typed model
  broker. Other architectures and overlapping mount roots fail closed.
- A supervisor-owned SQLite journal makes source/project/correlation unique,
  retains exact selection identity, fences dequeue and invocation, and prevents
  replay or restart from authorizing another invocation.
- `admission.py` orders a trusted policy's capture, post-queue authority check,
  repository preparation and invocation. **The production policy implementation
  and transport integration are not supplied.** Its component tests use fake
  policy methods and must not be represented as runtime freshness conformance.

`conformance.py` runs the actual patched Archon engine and native Codex CLI with
synthetic Responses events. It exercises real tools and a subsequent shell test,
checks a private Git commit, source replacement and write denial, an external
host canary, namespace/network denial, direct Unix-socket action denial, and the
absence of a disk engine database. It does not call a live model or publish work.
The tested native CLI is 0.149.0; this is not a compatibility promise for other
versions or for the existing deployment's native authentication/configuration.

## Reproduce the limited experiment

From the repository root with Bun 1.3.11 and dependencies installed:

```sh
bun test packages/core/src/operations/confined-workflow.integration.test.ts
python3 -m unittest scripts.confined_runtime.test_contract -v
bash scripts/build-confined-worker.sh /absolute/test-artifacts/confined-worker
python3 -m scripts.confined_runtime.conformance \
  --worker /absolute/test-artifacts/confined-worker \
  --node-distribution /absolute/approved/node-distribution
```

The host test account needs bubblewrap, libseccomp, Git, Python, Node and the
native Codex executable at `/usr/local/bin/codex`. Its `/usr` and Node mounts
must contain only approved toolchain inputs, not secrets. Use a disposable
account and repository. Do not run the probe as a privileged operator account.

The probe reports `full_runtime_conformance: false` and `live_acceptance: false`.
Its JSON is debugging evidence, not a Theseus VER report or verification result.
No VER1426 bindings are added here; #528 already owns its stale-context binding.

## Work required before support

1. Implement the trusted production policy: integrate bounded source staging,
   effective configuration validation, Theseus authority retrieval after dequeue,
   refreshed approved base and private worktree, and immutable execution records.
   The TS path walk requires a supervisor-owned staged tree with no concurrent
   writers. It is defense in depth, not a race-safe authoring-directory boundary.
2. Bind requested and executed closure, worker, native provider, native settings,
   toolchain and policy identities end to end. Version the adapter's existing
   three-file digest separately; it is not the Archon capture digest.
3. Supply authenticated private admission and complete source-scoped inspection,
   integrated with #524 ingress and #527 recovery. Unknown record versions and
   interrupted owners must remain blocked across upgrade. No stock API shim.
4. Implement and test permitted branch push, PR creation and progress brokerage,
   including hostile Git metadata and repository automation policy. Currently
   all publication/progress operations are denied. This does not satisfy the
   full allowed-work case.
5. Enforce aggregate process, memory, CPU and writable-storage budgets and
   supervisor/broker lifetime coupling. Bounded output and broker request quotas
   are not substitutes for those limits. LXC 121's test shell account currently
   has no delegated writable cgroup control.
6. Review native settings/guidance/authentication projection against the existing
   configured installation. The synthetic fixture config is not a replacement
   for it. Complete adversarial broker schema, upstream protocol and credential
   tests before allowing any real model credential.
7. Run the complete contract matrix and independent review against one exact
   release tuple. Only then may #528's refusal gate be replaced for that tuple.
   #531 owns operator packaging; #533 owns separately authorized live acceptance.

These source artifacts grant no merge, deployment, secrets administration,
verification disposition or release-readiness authority.
