# condor-scan

**A GCP privilege-escalation scanner that thinks in attack paths, not findings.**

> Install: `pip install condor-scan` · [PyPI](https://pypi.org/project/condor-scan/) · Apache-2.0 · Python 3.10+

condor-scan reads an export of your Google Cloud IAM and tells you not just
*who has dangerous permissions*, but *who can chain those permissions into full
control*, *which of them an outsider could reach*, *what the single highest-
leverage fix is*, and *whether you'd even see the attack in your logs*.

It started as a scanner for one specific, under-served escalation class —
tag-based IAM Conditions abuse — and grew an analysis layer on top that answers
the questions a security team actually argues about in triage.

---

## Why this exists

There is no shortage of GCP security scanners. Prowler, ScoutSuite, Forseti,
and the commercial CSPM/CIEM platforms all enumerate IAM misconfigurations
competently. After using them for a while you notice two recurring frustrations:

**They model permissions, not paths.** Most tools tell you "principal X holds
`iam.serviceAccounts.actAs`" as an isolated fact. They rarely tell you that X
can `actAs` a service account that is itself Owner on the project, which is the
thing that actually matters. Real GCP escalation is almost never a single step;
it's a chain — a leaked key leads to a default service account, which can
`actAs` a privileged one, which holds an org-level binding. Each link is
unremarkable alone.

**They miss tag-based conditional escalation entirely.** IAM Conditions let you
grant a role only when a CEL expression holds — for example, only on resources
tagged `env=prod`. That's a great feature. The problem: if a low-privileged user
can *attach that tag themselves*, they can satisfy the condition on demand and
collect the role. Mitiga documented this as "Tag Your Way In" in 2026, and
Google's position is that it's a customer-side misconfiguration — which means
it's your job to detect it, and almost nothing does, because almost everything
models only static bindings.

condor-scan is built around modelling the chain, and it treats tag-conditional
escalation as a first-class edge in that chain.

---

## What it actually computes

### 1. The escalation engine (capability closure)

The core is a small, deterministic engine that computes a **capability
closure**. For each principal it starts from the permissions and identities that
principal holds, then repeatedly applies escalation rules until nothing new can
be reached:

- **CONDOR-SETIAMPOLICY** — holding `*.setIamPolicy` lets you bind yourself
  Owner. Game over in one move.
- **CONDOR-ROLEUPDATE** — `iam.roles.update` on a custom role you hold lets you
  add any permission to it.
- **CONDOR-IMPERSONATE** — service-account impersonation: via Token Creator
  (mint an access token), via key creation, or via `actAs` combined with a
  deploy permission (deploy code that runs *as* the SA). When you reach an SA,
  you inherit everything it can do, and the closure keeps going from there.
- **CONDOR-TAGCONDITION** — the tag-based conditional path described above.

Because the closure only ever *adds* to the set of reachable capabilities and
the universe of permissions is finite, it always terminates. Every rule that
fires records a step, so the output is the full chain, not just a verdict.

That much is useful but not novel — it's table stakes for a serious tool. The
interesting part is what sits on top.

### 2. Exposure-aware origin analysis — *can an outsider reach this?*

A principal that can reach Owner is a problem. A principal that can reach Owner
*and is reachable from the internet* is an incident. Those deserve very
different priorities, and almost no scanner distinguishes them.

condor-scan models **untrusted sources**: the public IAM members `allUsers` and
`allAuthenticatedUsers` (when they're actually bound to something), plus any
identities you declare as internet-exposed in the export — for instance, the
service account attached to a public Cloud Run service. It then runs the closure
*from* those sources and marks every escalation finding that originates from, or
is reachable by, an untrusted identity.

The practical payoff: when the report says "2 externally exposed paths to Tier
Zero," those two go to the top of the queue regardless of how the raw severity
sorted them. This is the initial-access → privilege-escalation linkage that
turns a theoretical misconfiguration into a path you can reason about as an
attacker would.

### 3. Choke-point analysis — *what do I fix first?*

This is the part I'm most pleased with, and the reason the tool earns its keep
on a large estate.

Escalation findings are not independent. Cross an organisation with hundreds of
principals and you'll find that many distinct escalation chains funnel through
the *same* handful of IAM grants — one over-broad group binding, one shared
service account everyone can impersonate. If you remediate blindly down a
severity-sorted list, you do a lot of work for little structural gain.

condor-scan attributes every step in every chain back to the specific,
remediable grant that enabled it (a binding of *role → member on a resource*,
possibly conditional). It then treats "break every path to Tier Zero" as a
**minimum set-cover problem** over those grants and solves it greedily:
repeatedly pick the grant that addresses the most still-unaddressed escalating
principals.

Minimum set cover is NP-hard, so this is the standard greedy approximation
(the one with the classic `ln(n)` bound). I'm deliberately not pretending it's
optimal. What it gives you is the right *order* to work in: a prioritised
remediation plan where the first item is, provably, the single change that
collapses the most attack paths. In the bundled example, the top choke point is
one group binding that — removed — eliminates escalation for two principals at
once, ahead of five single-principal fixes.

One honest caveat, stated in the tool and again here: removing one grant on a
chain may leave an alternate sub-path intact, so you should re-scan after
remediating. The ranking is still the correct order; it just isn't a guarantee
that one removal fully neutralises a principal.

### 4. Detection-visibility mapping — *would we even see it?*

A path that generates no log is more dangerous than one that does, because it
defeats both detection and incident response. No misconfiguration scanner I know
of tells you this, and it's a genuinely important dimension.

Every escalation primitive is mapped to its MITRE ATT&CK (Cloud) technique and,
more usefully, to whether it produces a Cloud Audit Log entry **by default**.
The nuance that matters here is GCP-specific:

- **Admin Activity** logs are always on, free, and can't be disabled. They cover
  configuration-changing calls: `SetIamPolicy`, `CreateServiceAccountKey`, role
  updates, resource deploys, `CreateTagBinding`. Escalation that goes through
  these is visible.
- **Data Access** logs are *off by default* (BigQuery excepted), billable, and
  must be explicitly enabled. They cover most reads — including
  `GenerateAccessToken`, `GenerateIdToken`, and `SignJwt` on the IAM Service
  Account Credentials API.

So **service-account token impersonation is usually invisible** out of the box,
while key creation is logged. And **tag-based conditional escalation is invisible
in a subtler way**: the conditional binding already exists, so satisfying it by
attaching a tag emits only a `CreateTagBinding` event — never an IAM
policy-change event. Most SIEM detection content keys on policy changes, so it
simply never fires. condor-scan surfaces these silent paths explicitly as
"detection blind spots" so a SOC knows exactly where to turn on Data Access
logging or write tag-binding detections.

### 5. Temporal / JIT awareness — *is it exploitable right now?*

IAM Conditions are often time-bound. A break-glass procedure grants Owner for
four hours; a contractor's access expires at the end of an engagement; a
just-in-time access tool hands out short-lived elevation on demand. All of these
are expressed in CEL against `request.time`.

A scanner that ignores time gets two things wrong. It reports **expired** grants
as live escalations — a false positive that burns responder time chasing access
that no longer exists. And it has no way to flag the case that matters most for
live monitoring: a grant that is **active right now but only briefly**. A daily
CSPM sweep can miss a two-hour break-glass window entirely.

condor-scan parses the `request.time` bounds out of each condition and
classifies every conditional grant relative to an evaluation instant:

- **Expired** grants are dropped from the closure — they are no longer a path,
  so they are no longer a finding. (This also quietly fixes a real correctness
  bug the tool had before: a tag-conditional grant whose window had passed used
  to be reported as exploitable.)
- **Future** grants don't count as live escalation but are surfaced separately
  as *scheduled / dormant* — latent risk to review before it goes live.
- **Active** grants are analysed normally, and if the window is short-lived
  (below a configurable threshold, default 24h) the finding is flagged **JIT**
  with its expiry time. There is also a dedicated rule for an active, time-bound
  *direct* grant of an escalatory role — the literal break-glass case — which
  the engine would otherwise not surface at all.

Because the evaluation instant is injectable (`--as-of`), you can ask forward-
looking questions too: *what will be exploitable next Monday at 09:00?* The same
export, evaluated at two different instants, gives two different answers — which
is exactly right.

---

## Installation

condor-scan is published on [PyPI](https://pypi.org/project/condor-scan/):

```bash
pip install condor-scan
```

This installs the `condor-scan` command. To work on the project from a checkout
instead, with the test and lint tooling:

```bash
pip install -e ".[dev]"
```

The analysis core has **zero runtime dependencies** — it's pure standard
library. That's a deliberate choice for a security tool: the fewer third-party
packages in the dependency tree, the smaller the supply-chain attack surface you
take on by running it. Live Cloud Asset Inventory ingestion is the one optional
extra (`pip install ".[cloud]"`), since it pulls in the Google client library.

Python 3.10+.

---

## Usage

### Scan for escalation chains

```bash
condor-scan scan export.json                    # human-readable table
condor-scan scan export.json --format json      # machine-readable, ATT&CK-enriched
condor-scan scan export.json --format sarif      # SARIF 2.1.0 for CI dashboards
condor-scan scan export.json --fail-on critical  # non-zero exit to gate CI
```

### Run the attack-path posture report

This is the triage / executive view — exposure, the remediation plan, and blind
spots in one place:

```bash
condor-scan posture export.json
condor-scan posture export.json --format json
condor-scan posture export.json --fail-on-exposed   # CI gate on internet-reachable Tier Zero

# Temporal questions: evaluate time-bound conditions at a chosen instant.
condor-scan posture export.json --as-of 2026-12-01T09:00:00Z
condor-scan posture export.json --jit-threshold-hours 4      # what counts as "short-lived"
condor-scan scan    export.json --as-of 2026-12-01T09:00:00Z # scan also honours --as-of
```

Example output against the bundled `examples/sample_export.json`:

```
condor-scan - attack-path posture report
================================================
Principals analyzed .............. 10
Escalation findings .............. 8
Can reach Tier Zero .............. 8
Externally exposed -> Tier Zero .. 2
Remediation budget (choke points)  7
Detection blind spots ............ 4

EXTERNALLY EXPOSED PATHS TO TIER ZERO (fix first):
  ! serviceAccount:frontend@demo-prod.iam.gserviceaccount.com
  ! serviceAccount:privileged@demo-prod.iam.gserviceaccount.com

PRIORITISED REMEDIATION PLAN (greedy choke-point cover):
  1. remove/scope: roles/owner -> group:platform@example.com on .../projects/demo-prod [condition: only-prod-tagged]
     -> eliminates escalation for 2 principal(s): user:alice@example.com, user:grace@example.com
  ...

DETECTION BLIND SPOTS (escalation with no default audit signal):
  ~ [CONDOR-TAGCONDITION] user:alice@example.com: attach tag to satisfy condition 'only-prod-tagged' ...
  ~ [CONDOR-IMPERSONATE]  user:bob@example.com: impersonate 'privileged@...' via 'iam.serviceAccounts.getAccessToken'
```

### Generate preventive policy

The same logic that detects tag-conditional escalation can run *preventively* as
an OPA / Policy Library constraint at deploy time (Terraform validation, a CI
gate) rather than only as an after-the-fact scan:

```bash
condor-scan gen-constraints --out-dir ./policy
```

This emits a Rego constraint template plus an instance compatible with the
Config Validator / Gatekeeper ecosystem that Forseti's `policy-library`
consumes. It's deliberately decoupled: the constraint stands on its own and can
be adopted by Google's open-source policy tooling without depending on this
project at all.

---

## Getting the input

condor-scan reads a JSON shape close to a Cloud Asset Inventory export:

```bash
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json
```

You massage that into the documented schema (`roles`, `iam_policies`,
`tag_bindings`, `group_members`, `exposed_principals`). See
`examples/sample_export.json` for a complete, commented-by-example file. The
`load_from_cloud_asset_inventory()` stub in `loaders.py` sketches the direct
client integration for when you want to skip the manual export.

The `exposed_principals` list is how you feed in network reality — your CSPM,
load-balancer config, or Cloud Run/Functions inventory knows which service
accounts sit behind public endpoints; list them here and the exposure analysis
becomes meaningful.

---

## Architecture

```
loaders.py      parse CAI/JSON export ─────────► model.py     typed domain objects
                                                     │
analysis.py     index: per-principal permissions, impersonation maps,
                grant provenance, exposure sources
                                                     │
rules.py        capability-closure engine ────────► findings.py  Finding + JSON/SARIF/table
                (attributes each step to a remediable grant)
                                                     │
graph.py        attack-path intelligence: exposure, choke-point
                set-cover, detection blind spots ──► PostureReport
                                                     │
techniques.py   MITRE ATT&CK + audit-log visibility model
temporal.py     request.time window parsing + JIT/expiry classification
constraints.py  preventive OPA/Rego policy generator
cli.py          argparse front-end (scan / posture / gen-constraints)
knowledge.py    curated escalation primitives + predefined-role subsets
cel.py          conservative tag-condition (CEL) parser
```

The split is intentional: indexing is pure and cacheable, the engine is pure
graph traversal, and the intelligence layer is pure analysis over the engine's
output. Each layer is independently unit-testable, which is why the test suite
can isolate, say, the greedy set-cover from the closure from the CEL parser.

---

## Limitations (read these — a security tool that oversells its coverage is dangerous)

- **The CEL parser is conservative by design.** It recognises
  `resource.matchTag(...)` and `resource.matchTagId(...)` predicates. Other
  condition types (time, IP, request attributes) are treated as *not*
  tag-satisfiable — the low-false-positive default. It is not a full CEL
  evaluator.
- **Tag-attach capability is modelled broadly.** Holding
  `resourcemanager.tagValueBindings.create` is treated as "can attach tags."
  Real GCP additionally requires `tagValues.use` on the specific tag value, so
  this can over-report; verify a tag-condition finding against the specific
  tag's IAM before acting.
- **The role→permission map is a curated escalation-relevant subset**, not a
  full mirror of GCP IAM (which has tens of thousands of permissions). Custom
  roles are read verbatim from the export. Keeping the map curated is what keeps
  false positives low and the output auditable.
- **Choke-point cover is a greedy approximation**, and removing one grant may
  leave an alternate path — re-scan after remediation. The ranking is the right
  order to work in, not a uniqueness proof.
- **Exposure is only as good as the `exposed_principals` you provide.**
  `allUsers`/`allAuthenticatedUsers` are detected automatically; everything else
  (public Cloud Run/Functions SAs, etc.) you supply.
- **Resource-hierarchy inheritance** (org → folder → project) is modelled per
  policy resource, not as full inherited-binding propagation.
- **Temporal parsing is limited to `request.time` vs `timestamp('...')`.** Other
  time expressions (durations, `request.time.getHours()`, recurring windows) are
  treated as unbounded on that side — the conservative default. Evaluation uses
  a single instant; it does not reason about recurring schedules.

These are written down on purpose so findings are interpreted correctly rather
than trusted blindly.

---

## Development

```bash
pip install -e ".[dev]"
make check          # the full gate: ruff + mypy --strict + pytest
make test           # pytest with coverage
make demo           # run the scanner against the bundled example
```

The project holds itself to: **ruff** clean, **mypy `--strict`** clean across
every module, and a **pytest** suite (72 tests, ~96% coverage) that exercises
every escalation path with both positive and negative cases, the set-cover
algorithm, the exposure logic, the blind-spot detection, the temporal/JIT
classification, and the CLI end to end.

---

## Releasing (maintainers)

Releases are built with [`build`](https://pypi.org/project/build/) and uploaded
with [`twine`](https://pypi.org/project/twine/):

```bash
python -m pip install --upgrade build twine
rm -rf dist build *.egg-info
python -m build                      # produces dist/*.whl and dist/*.tar.gz
twine check dist/*                   # validate metadata renders on PyPI
twine upload dist/*                  # authenticate with a PyPI API token
```

Bump `version` in `pyproject.toml` (and `__version__` in
`src/condor_scan/__init__.py`) for each release; PyPI refuses to overwrite an
existing version. Consider testing against TestPyPI first, or wiring GitHub
Actions Trusted Publishing so no token ever leaves CI.

## License

Apache-2.0. See `LICENSE`.
