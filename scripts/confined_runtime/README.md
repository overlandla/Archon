# Immutable confined handoff runtime — Theseus #778

This companion runtime implements the source contract for
[Theseus #778](https://github.com/overlandla/theseus/issues/778). It is based on
Archon v0.10.0 `c8f439a0269fee0f33f2f9f64752d66860112274`, the inspected installed
binary revision. It does not replace the existing GitHub/Codex/Telegram service.

The Theseus adapter registry remains empty. These source changes and controlled
synthetic tests are **not an attestation of an operator release or live acceptance**.
Do not enable the connector merely because a runtime advertises this protocol.

## Runtime composition

`Runtime(Journal, Profile)` is the trusted policy supplied to `Supervisor` and
`control.Server`. The server binds only literal IPv4 loopback with a private bearer
credential. #524 remains the sole ingress; #422 remains the canonical handoff
producer. There is no task-model or connection-settings change.

The profile pins workflow identity and complete closure revision, worker/native
provider binaries, OCI image, native settings, authority-reader/supervisor and
Python dependency contents, plus the complete public authority configuration.
Operator credentials stay in trusted broker objects; no caller request supplies
credentials, Docker options, callbacks, endpoints or provider settings.

The runtime journals source/project/correlation and the exact immutable selection
before acknowledgement. Dequeue and invocation each use irreversible revision
fences. Replay observes the same record; changed reuse conflicts. Interrupted
owners and uncertain effects cannot be retried automatically. Unknown journal
schemas are rejected, and upgrades must preserve existing records.

After dequeue, the runtime stages the approved capture without links, hardlinks or
special files and validates its complete executable closure. It calls the Theseus
adapter's canonical authority reader before base resolution and again at bootstrap
before Git initialization/fetch. Only successful checks permit the fixed remote's
current base to be fetched and checked out inside the confined worker. A stale
bootstrap remains uncertain with a bounded retained rejection diagnostic.

The immutable image runs the actual Archon engine, native Codex, model tools and
shell test nodes. Linux x86-64 OCI enforcement checks non-root UID, read-only root,
no network, dropped capabilities, seccomp, no-new-privileges, private namespaces,
128 PIDs, 1 GiB memory/no additional swap, two CPU quota and finite writable tmpfs
mounts. The worker has neither Docker/SSH sockets nor operator home/credentials.
Only individual typed broker sockets are mounted. PID1 and engine control memory
are protected from same-UID descendants. Engine completion uses a one-shot
protected descriptor, not a worker-writable result file or HTTP claim.

A detached watchdog expires the pre-recorded container after supervisor death. It
checks owner label, image and name, deletes the inspected immutable ID, and retries
bounded individual daemon operations until absence/removal is confirmed. A daemon
outage retains cleanup ownership; it does not prove the worker has stopped.

## Typed authority

- Model brokerage accepts the pinned model's bounded Responses vocabulary and
  local tools only. Provider credentials never reach Codex or its descendants.
  Remote tools, redirects, ambient proxies and arbitrary provider endpoints fail.
- Git read brokerage permits only bounded upload-pack access to the configured
  repository and refreshed commit. Worker Git metadata cannot select host Git
  configuration, helpers, credentials, hooks or a remote destination.
- Export accepts bounded regular files/deletions with content and executable-mode
  identity. Publication validates the complete base/result trees and explicit
  allowed paths, retains the candidate commit before the external write, and
  creates one new run-specific ref plus a draft PR through fixed GitHub operations.
  Existing refs cannot be updated. A lost acknowledgement blocks further writes.
- Publication requires GitHub Actions disabled and a separately established
  operator profile isolating other automation. The runtime does not disable
  automation or infer that other deployment triggers are absent.
- Progress binds task/scope/work-unit/graph/correlation identities and permits
  implementation progress only. Approval, merge, deployment, secrets management,
  verification disposition and release readiness have no broker operation.

Unsupported workflows/providers, dynamic closures, ambient authoring scopes,
plugins/MCP, alternative native configurations and unrestricted outer execution
are rejected. The older bubblewrap scripts remain historical probes; they do not
supply the aggregate budgets of the OCI candidate.

## Controlled reproduction

Use a disposable test environment with Bun 1.3.11, Python, Docker, the Theseus
adapter dependency installed, and the approved native Codex ELF. The tested native
binary is CLI 0.149.0; its SHA-256 is recorded in test output. Do not copy operator
homes or credentials into build inputs. The fixed Dockerfile pins its base image.

```sh
bash scripts/build-confined-worker.sh /absolute/build-inputs/worker
# Place the approved native ELF at /absolute/build-inputs/codex.
cp scripts/confined_runtime/gateway.py scripts/confined_runtime/oci_gateway.py \
  scripts/confined_runtime/git_gateway.py /absolute/build-inputs/
docker build --network=none -f scripts/confined_runtime/Dockerfile \
  -t archon-confined-test /absolute/build-inputs
# Resolve the immutable image ID; never pass a mutable tag to the runtime.
docker image inspect --format '{{.Id}}' archon-confined-test
python -m scripts.confined_runtime.controlled_suite \
  --image sha256:<resolved-image-id> \
  --worker /absolute/build-inputs/worker --native /absolute/build-inputs/codex \
  --output /absolute/new-test-output-directory
```

The suite runs component checks, actual engine/native tool and shell confinement,
engine death/forged completion, typed publication/progress and lost acknowledgement,
actual upload-pack fetch, supervisor death, and concrete policy composition. The
composition covers current execution, queued and bootstrap stale scope/guidance,
unavailable authority, executable-mode tampering and partial broker startup.
Only model/Theseus/GitHub replies are synthetic; no live writes or model calls occur.

Run the TS entry integration test and `bun run validate` separately. The Theseus
adapter's PostgreSQL suite checks complete tuple approval and durable claim/recovery,
including wrong-selection and unknown-format rejection. No new VER1426 scenario
bindings are added: #528 owns its stale-context binding. Allocation of nominal and
excluded-action live evidence remains with #533, without duplicate markers.

## Operator packaging handoff (#531 / #533)

Packaging must protect the immutable code, profile, capture, Python environment,
journal and brokers from the worker and other untrusted writers; provide a private
Docker daemon/enforcement service and supervised watchdog ownership; bound the
supervisor's own storage/lifetime; and preserve the journal across restart/upgrade.
Only a separately reviewed complete release/profile may be placed in the adapter's
source-controlled registry. Changing any pinned field invalidates that approval.
Lookup remains available after a gate closes and uses the original durable release.

The [packaging candidate](packaging/README.md) now supplies a strict service entry,
separate durable cleanup unit, dedicated daemon configuration and bounded staging.
It has not been installed or approved as an operator profile.

This library intentionally supplies no secret-administration or deployment command.
#531 owns installation and service/credential provisioning. #533 owns separately
authorized live acceptance against the exact packaged profile. No existing live
configuration has been replaced, and no verification or readiness disposition is
implied by the controlled results.
