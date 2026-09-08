# Dedicated LXC controlled checks

These opt-in helpers exercise an installed candidate with actual systemd, HTTPS,
Git, Archon, native Codex and OCI execution. External authority, GitHub, model and
publication responses are synthetic. They do not connect a live Theseus adapter,
approve a release, publish a real PR or create accepted verification evidence.
Use only an explicitly authorized, dedicated test LXC. Preparation stops the
existing Archon service and temporarily changes host name resolution and TLS
trust; keep other automation stopped until restoration completes.

## Installation inputs

Follow `packaging/README.md` for the immutable release, protected identities,
credentials, private daemon and bounded storage. Root-owned public release files
and installed units must be readable by their service identity: directories 0755,
public files 0644, executables 0755; credentials and state remain private. Copy the
Theseus adapter's source `archon_adapter/test_support.py` to the root-only
`/var/lib/archon-conformance/test_support.py`. The production wheel deliberately
omits it. The separate fixture process loads this copy; the admission service does
not. Retain the exact adapter commit and hashes with the build inputs.

The tested dedicated Ubuntu 24.04 LXC has cgroup v2 and a private AppArmor namespace.
Its named `runc` profile blocked Docker's `pivot_root`. Install the exact packaged
`packaging/runc-local.conf` as `/etc/apparmor.d/local/runc`, root-owned 0644, then
reload `/etc/apparmor.d/runc` using `apparmor_parser -r`. This permits pivoting only
beneath the private daemon's storage root. Do not overwrite an existing local rule,
disable AppArmor or change the outer Proxmox profile. The admission startup checks
the installed rule's bytes and ownership. Loaded AppArmor policy, parent profile,
namespace isolation and kernel remain independent operator-review inputs.

This LXC has `/dev/fuse` but no loop devices. For controlled tests, bounded sparse
ext4 images mounted through `fuse2fs -o rw,allow_other` provide 1 GiB journal and
16 GiB daemon filesystems. With `fuse2fs` installed and the `archon-confined` user created,
`venv/bin/python -B -m scripts.confined_runtime.lxc_storage_conformance` provisions
fresh volumes and refuses existing targets. Place their root-only backing files under
`/var/lib/archon-conformance`. Never format a host block device. Use persistent
systemd mount-helper services ordered before `local-fs.target` and the candidate
units, with `DefaultDependencies=no`, `After=local-fs-pre.target`, and
`Conflicts=umount.target`, `Before=umount.target`. Use `Type=forking` and an exact
`umount` ExecStop. Confirm mountpoints and ownership before starting the daemon.
Remove only each newly created filesystem's empty `lost+found` directory. FUSE
and its backing storage are part of this candidate profile; their use is not a
claim that every LXC storage configuration is supported.

Import the retained image into the dedicated socket. The fixture currently pins
its worker image in `installed_conformance.py`; changing it requires rebuilding
the selection and collecting fresh evidence. The Docker client always uses the
versioned empty `packaging/docker-client/config.json`, ignoring ambient client
proxy configuration.

## Run

From `/opt/archon-confined/release`, as root, using the installed venv:

```sh
venv/bin/python -B -m scripts.confined_runtime.installed_conformance prepare --worker /retained/build/worker
```

Preparation refuses an existing profile or fixture selection. It creates only
synthetic credentials and workflow inputs. Keep the generated root-private
backups. Run the fixture as a separate root systemd service:

```ini
[Unit]
Description=Synthetic external replies for Archon installed conformance

[Service]
WorkingDirectory=/opt/archon-confined/release
ExecStart=/opt/archon-confined/release/venv/bin/python -B -m scripts.confined_runtime.installed_conformance serve
UMask=0077
Restart=on-failure
RestartSec=2
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Install that unit as `archon-conformance-fixtures.service`. Start it, the private
daemon, cleanup and admission units. Then run each check separately:

```sh
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance nominal
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance basic
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance configuration
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance storage
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance crash
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance reboot_prepare
systemctl reboot
# After reconnecting, from the same release directory:
venv/bin/python -B -m scripts.confined_runtime.installed_checks_conformance reboot_check
```

Storage checks fill only explicitly named test files on the three bounded
filesystems and remove those files in `finally`. Filling the 16 GiB FUSE volume
can take several minutes and allocates backing space on the parent filesystem.
Reserve that capacity first. Crash checks kill the admission and cleanup main
processes, pause only the private daemon across the recorded worker expiry, then
resume it and require exact-container cleanup without reinvocation. Do not rerun
with a new correlation to recover a lost acknowledgement. Nominal and crash
checks retain their correlation before the relevant irreversible boundary; an
ambiguous lookup stops the test.

`installed-checks.json` retains successful assertions and the complete release
selection. A failed command is not a passed case; retain command logs alongside
this report. It always reports `full_runtime_conformance: false` and
`live_acceptance: false`. Preserve each release's report separately before changing
policy inputs. Never reset journal history to make a new candidate pass.

## Restore

After checks, with the private daemon still running, execute:

```sh
venv/bin/python -B -m scripts.confined_runtime.installed_conformance restore
```

This stops admission, requires no remaining containers, verifies the exact
synthetic hosts/CA additions, stops and disables test services, restores original
network inputs and restarts the original Archon service if it was previously
active. Unexpected network changes stop restoration for operator reconciliation.
It retains all journal records, build inputs and evidence. After services drain,
stop and disable the two test storage helpers and stop the staging mount. Retain
the backing images; exhaustion testing can leave allocated blocks even after
filler deletion. Any offline space reclamation must target only these test-owned
images and preserve their contents.

Independent review must still establish the complete maintained operator profile,
host dependencies, repository automation isolation and credential scope before
any complete-release approval. Live acceptance remains a separate authorized step
owned with Theseus #533; preserve #528's existing VER scenario binding.
