# Allocated child execution candidate

Companion runtime integration for [Theseus #816](https://github.com/overlandla/theseus/issues/816),
built on the maintained #778 runtime. This source does not approve a release,
install a service, or authorize live work. The adapter's complete-release registry
remains the execution gate.

The authenticated loopback control server adds `/v2/children/contract`,
`admissions`, `lookup`, `inspect`, `notify`, `reconcile`, and `stop`. The existing
`/v1` single-repository protocol remains available. Only the existing Theseus
Archon adapter may call either protocol; this runtime does not produce handoffs.

Admission receives the unchanged complete allocation and selected child UUID.
The persisted run binds its source, parent, child, correlation, whole allocation
digest and selection digest. Complete source-scoped lookup returns that same
binding. Admission replay returns the original run; a changed selection cannot
reuse its correlation. Neither restart nor uncertain lookup puts an invoked run
back on the queue.

Each runtime instance still has one fixed repository and complete release tuple.
The adapter selects a separate reviewed instance/profile for each repository.
A child's fixed mapping selects its reserved absolute workspace and pinned
commit. The supervisor reserves ownership after checking canonical authority.
The worker uses a bounded private OCI tmpfs at that exact path, fetches the pinned
commit through the fixed repository broker, and checks it out detached. The host
reservation is supervisor-owned metadata, never a writable worker mount.
Publication retains the existing base and automation checks; a moved base can
prevent publication without repinning execution.

Child progress remains an observation in the private runtime journal. Successful
publication receipts become artifacts attributed to the child's canonical
Theseus repository reference. The runtime never sends child progress directly to
Theseus. The adapter owns canonical delivery and aggregate completion. Observation
versions cover a consistent snapshot of runtime state, controls and artifacts.

Stop and scope controls retain exact child/run-bound intents. They fence dequeue,
effects, bootstrap consumption and terminal completion. An affirmative stop or
scope-block reply requires either a not-started run or a drained worker owner;
unknown ownership remains uncertain. A terminal result is not overwritten.

Successor consumption has a deliberate restriction: an associated run still in
`admitted` can consume a newly authorized canonical handoff before its first
provider invocation. The worker must receive positive supervisor permission
for that exact consumed scope before proceeding. Reconciliation replay confirms
only that exact retained decision. An already-invoking worker is drained and
remains blocked; this candidate does **not** resume that provider under successor
scope. The caller must not interpret `consumed: false` as permission to relaunch.

The existing packaging is a single-profile candidate. Multi-instance service,
journal, workspace, credential and aggregate resource isolation still need #778
packaging/conformance review. Do not copy the fixed-path systemd units into
parallel instances or broaden their writable paths based on these source tests.
#533 owns separately authorized installation and live qualification. Synthetic
source/GitHub/model replies and local Docker tests establish no installed-runtime
or live-acceptance verdict.
