# Confined runtime packaging candidate

This is the maintained-fork packaging slice for
[Theseus #778](https://github.com/overlandla/theseus/issues/778), based on
`theseus-v0.10-base`. It composes the existing runtime; it does not replace the
stock Archon service, expose its API, approve a release, or install anything.
The Theseus complete-release approval registry stays empty. No operator profile
or live VER evidence is supplied by this package.

See [dedicated LXC controlled checks](../INSTALLED-CONFORMANCE.md) for the opt-in
installed-service harness, its temporary host changes and restoration procedure.

## Exact supported candidate topology

The candidate requires Linux x86-64, systemd with `LoadCredential`, cgroup v2,
Docker with the systemd cgroup driver, containerd 2 with version-3 configuration,
`fuse-overlayfs`, and a root-owned dedicated Python 3.13+
environment containing the pinned Theseus adapter and all dependencies. Record
the exact OS, kernel, systemd, Docker/containerd/runc, Python, TLS trust-store and
native library identities in the operator review. These are host enforcement
inputs; the Python policy digest alone is not an attestation of them.

`archon-confined.service` runs as the distinct `archon-confined` user. It loads
only a root-owned public profile and four systemd credentials. Its listener is
literal loopback; only the #524 adapter receives the ingress credential. There
is no generic executable, import, callback, credential-path or Docker override
in the profile. Existing Archon connection settings remain separate.

`archon-confined-docker.service` owns a separate Unix socket, data directory,
exec directory and explicitly selected `archon-confined-containerd.service`.
That service owns `/run/archon-confined-containerd/containerd.sock` and stores
content under the same bounded daemon filesystem. Docker must never discover or
reuse `/run/containerd/containerd.sock`. The fixed `fuse-overlayfs` storage driver supports
the candidate FUSE filesystem; overlayfs and erofs plugins are disabled there.
Containerd configuration imports, CRI and NRI are disabled. Docker’s
[containerd storage documentation](https://docs.docker.com/engine/storage/containerd/)
explains why setting Docker’s data root alone does not bound containerd storage. It has no TCP listener or network bridge.
The two trusted runtime units see its socket at `/run/docker.sock` through a
read-only bind; they must never join the host's general `docker` group. Access
to this dedicated daemon remains powerful trusted supervisor authority. It is
not safe to give its socket or the `archon-confined` identity to model workers,
repository automation, interactive agents or the existing Archon service.

The Docker client uses the versioned empty `docker-client/config.json`; ambient
service-account proxy configuration is not an execution input. The installed
`/etc/apparmor.d/local/runc` must match `runc-local.conf`. This candidate targets
the dedicated Ubuntu LXC profile described in the installed-check guide; loaded
AppArmor policy still requires independent operator review.

The original per-worker detached watchdog stays enabled. A second, independently
supervised `archon-confined-cleanup.service` reads the durable ownership facts and
repeatedly removes expired exact-name/image/label containers by inspected immutable
ID. It retains uncertainty after daemon failures or identity mismatch, never
changes admission/effect state and never retries invocation. It has no model,
Theseus, GitHub or ingress credential. It announces readiness only after an initial complete healthy journal scan.
It survives an admission-service stop;
`BindsTo` stops admission if its cleanup unit disappears. The daemon starts cleanup again with a fresh socket mount after recovery. Start admission
explicitly after repairing either dependency; do not infer permission to replay
interrupted rows. The aggregate worker slice bounds overlapping orphan workers.

## Protected layout and budgets

| Path | Ownership and purpose |
| --- | --- |
| `/opt/archon-confined/release` | Root-owned immutable release, venv, code and `capture/`; no editable dependencies or group/other writable inputs |
| `/etc/archon-confined/profile.json` | Root-owned public exact selection; 64 KiB maximum; no secret values |
| `/etc/archon-confined/credentials/{ingress,theseus,github,model}` | Root-only source files, injected by systemd; distinct least-privilege credentials |
| `/var/lib/archon-confined` | Dedicated persistent filesystem, at most 2 GiB, service-owned mode 0700; journal and owner locks only |
| `/var/lib/archon-confined-docker` | Separate bounded persistent filesystem, root-owned mode 0700; dedicated image/container storage |
| `/tmp/archon-confined-runtime/work` | Service-owned mode 0700 on the supplied 512 MiB tmpfs mount; transient captures, sockets and exports |

Provision persistent volumes before installation, for example a 1 GiB XFS volume
for journal state and an 8 GiB XFS volume for daemon storage. Register their mounts
in the host's mount configuration. The units require actual mountpoints; the
service additionally rejects a journal filesystem larger than 2 GiB. Verify and
retain the daemon volume's finite size as part of operator conformance. Never
format, seed or reuse another installation's volume. Keep filesystem-maintenance
folders outside the journal directory: startup rejects unexpected directories,
links and public files there. A full volume causes failure, never journal pruning
or automatic retry. Image import, retention and upgrades must fit the reviewed
daemon volume budget.

Staging is deliberately shared with the daemon's host namespace. `PrivateTmp=yes`
on the admission unit would break Docker source mounts. The supplied mount and
root-owned parent keep the bounded staging path fixed. Container-only root-owned
traversable tmpfs ancestors prevent graph-driver mount creation from inheriting
the host staging directory’s private mode; host permissions stay private. Do not clean staging while
any container may still reference it. On a drained upgrade, remove only retained
run-specific temporary directories after confirming all associated containers
are absent. Reboot clears staging; durable admissions still prevent reinvocation.

## Assemble a reviewable release before operator installation

1. Start from the pinned fork commit. Build the worker with the existing
   `scripts/build-confined-worker.sh`, obtain the exact native provider binary,
   and build the immutable OCI image using the parent README. Retain their hashes
   and build inputs. Never copy a credential-bearing provider home into the image.
2. Build the Theseus adapter wheel from its exact selected source commit. Create
   a dedicated Python environment using a copied interpreter; install the wheel
   and its fully pinned, hash-checked dependencies from a retained wheelhouse.
   Use copy mode, not editable installs or hardlinks into writable package caches.
   Retain the lock, wheel hashes, interpreter/stdlib and OS package inventory.
3. Assemble the release at its final path on a disposable conformance machine.
   Copy `scripts/__init__.py` if present and `scripts/confined_runtime/` under the
   release root. Place the environment at `venv/` and the engine-produced immutable
   workflow capture at `capture/`. Make the complete tree root-owned and
   non-writable by service or worker identities. Venv links may target only
   root-protected OS or release files. Admission, cleanup and watchdog use `-I -S -B -X pycache_prefix=/dev/null`
   through the same source-only bootstrap. It compiles Python source directly,
   rejects sourceless/ZIP imports, skips `.pth` and `sitecustomize`, and adds only
   the fixed venv dependency directory. The release root is never a general
   import root. Interpreter startup bytecode/ZIP inputs are also hashed; native
   loader libraries remain part of the separately reviewed host inventory.
4. Produce the complete release tuple using `Release`, closure inspection,
   `policy_identity.revision()`, the native configuration digest and
   `Profile.configuration_revision()` from that final environment. The policy
   digest includes the packaged unit, mount, slice, daemon JSON and containerd TOML configuration files.
   Preserve all eight release identity fields; never approve only the image or
   binary. The digest also covers all importable source/extensions in the scripts and
   dependency roots, including files absent from wheel RECORDs. Directory symlinks
   inside import roots are unsupported; explicit interpreter/venv layout aliases remain allowed. Changing packaging,
   installed import contents or startup artifacts invalidates previous policy evidence.
5. Prepare `profile.json` using the structure below and synthetic credentials for
   controlled testing. Compare the selected repository mapping with the canonical
   #524 mapping. Allowed paths must be explicit regular-file paths. Independently
   establish that Actions are disabled and all other repository automation is
   isolated; the profile's automation string is a declaration, not proof. The
   existing Theseus repository has deployment automation, so do not assume it is
   a suitable publication target.

```json
{
  "format": "archon-operator-profile-v1",
  "release": {
    "format": "archon-confined-experimental-v1",
    "identity": "theseus-implementation",
    "closure_revision": "REQUIRED_SHA256",
    "worker_revision": "REQUIRED_SHA256",
    "provider_revision": "REQUIRED_SHA256",
    "confinement_revision": "REQUIRED_SHA256",
    "policy_revision": "REQUIRED_SHA256",
    "native_configuration_revision": "REQUIRED_SHA256",
    "authority_configuration_revision": "REQUIRED_SHA256"
  },
  "port": 8788,
  "source": {"deployment": "https://source.example.invalid", "project": 1000},
  "model": "REQUIRED_MODEL",
  "model_origin": "https://model.example.invalid",
  "selected_repository": {
    "canonical_ref": "github:owner/repository",
    "repository": "/approved/repository",
    "worktree_root": "/approved/worktrees",
    "base": "main"
  },
  "owner": "owner",
  "repository": "repository",
  "repository_id": 1,
  "allowed_paths": ["src/implementation.py"],
  "automation_mode": "operator-isolated-actions-disabled"
}
```

This example deliberately cannot pass validation. No example is a release approval.
Credentials contain 32–8192 printable ASCII characters with an optional final LF;
private source files should have mode 0600. The service rejects links, hardlinks,
public modes and header/control characters, and emits only fixed failure codes.

## Separately authorized installation and acceptance

After the package/profile review and explicit operator authorization:

- Create the service identity without interactive login or membership in other
  privileged groups. Provision the two private volumes and protected layout.
- Copy the `.service`, `.slice` and `.mount` files to `/etc/systemd/system/`
  unchanged. No unreviewed drop-ins are supported. Reload systemd. Startup compares
  installed copies with the hashed release and rejects pending daemon reloads.
  The Docker unit creates staging with the supplied tmpfiles file after mounting.
- Import the exact immutable image into the **dedicated** Docker daemon. A mutable
  tag or an image existing only in the general host daemon is insufficient.
- Validate the profile with the packaged entry's `check` mode under the same unit
  identity, credential injection and mounts in the disposable harness. Then run
  the actual service composition there with synthetic external responses.
- Retain effective unit settings, mount/ownership checks, daemon and aggregate
  worker resource enforcement, credential-denial probes and test results against
  the exact source and profile. Only after independent conformance review may a
  separate Theseus source change approve that complete tuple.
- Live #533 acceptance, public adapter routing and live credentials remain a
  separate authorization. Keep runtime ingress private; do not proxy it publicly.
  Do not duplicate #528's stale-context VER binding or submit verification disposition.

## Restart, upgrade and compatible rollback

Stop admission first. Leave cleanup and the dedicated daemon running until every
retained owner is absent; a timeout or unavailable daemon is unresolved. Check
both admission and publication-effect journals, preserving uncertain rows. Back up
the SQLite database using its backup API while writers are stopped; retain the
matching release/profile and image alongside the backup inventory, without secrets.
Never copy only the main database while an uncheckpointed WAL is present.

A release replacement is an operator operation performed while admission and
cleanup are stopped and all workers are confirmed absent. Preserve the journal
volume. Install the reviewed code/profile/unit combination, reload systemd, start
the daemon and cleanup, validate and explicitly start admission. Schema 1 remains
unchanged; unknown schema versions fail before listening. Compatible rollback
uses the retained matching release and profile against the existing journal;
it must not restore an older database and erase invocation/effect history.

A paused, checking, invoking or uncertain run remains blocked after restart.
Neither rollback, cleanup acknowledgement nor an empty correlation result grants
another invocation. Reconcile through #527 using the original retained selection.

## Validation allocation

`test_service.py` covers strict profile composition, credential denial, exclusive
ownership, durable expiry cleanup after restart/daemon failure, bounded scan
progress, unchanged invocation state and unknown schema rejection. Existing
`test_watchdog.py` covers exact-object deletion and daemon timeouts. Run all
component tests plus the parent's controlled matrix and `bun run validate`.
The controlled matrix imports `archon_adapter.test_support`, which is deliberately
excluded from the production wheel. Set `PYTHONPATH` to the selected Theseus
checkout's `services/archon-adapter` directory for that synthetic test process
only. Retain its source revision; the installed `-I` service never uses that path.

These source tests do not prove the systemd/volume/cgroup/credential boundary on an
installed host. The disposable installation must additionally exercise admission
SIGKILL, cleanup SIGKILL/restart, daemon outage across expiry, host reboot, full
journal/staging/daemon volumes, unprivileged reads, socket denial, unit drift and
unreviewed profile changes. Keep `full_runtime_conformance` and `live_acceptance`
false until their respective evidence and authorization requirements are met.
