# Upwind findings → Cherwell change requests

## Why this is the hardest of the four duties

The other three duties end in a decision you can take. This one ends in a decision **somebody else** takes, on their own schedule, on infrastructure you must not touch. Your entire output is a change request, and a CR is only as good as its ability to survive CAB without a round trip.

So the quality bar is specific: **a CR that an engineer who has never seen the finding can execute, and a CAB member who is not in security can approve.** Anything that requires the reader to go and look at Upwind has failed.

## What Upwind gives you that a scanner does not

Upwind is runtime-aware. That changes prioritization more than any CVSS score does, and it is the reason the queue is workable at all:

- **Is the vulnerable package actually loaded?** A CVE in a library present on disk but never loaded into a running process is not the same risk as one in a hot code path. This is the single most useful field in the finding.
- **Is the workload internet-reachable?** Observed network exposure, not the theoretical exposure implied by a security group.
- **Is the asset running at all?** Findings against images that no longer have running instances are a registry-hygiene problem, not a patching problem.
- **What talks to it?** The observed dependency graph tells you the blast radius of the change — which is the question CAB will ask.

Use these to rank. Use CVSS and EPSS to break ties, never to lead. A critical CVSS on a dormant library loses to a high CVSS on an internet-exposed, running, in-use one every time.

## Change groups: the unit is the change, not the finding

**One CR per remediation action that a single team executes together.** Group by:

```
(owner team, environment, fix type, fix target)
```

- **owner team** — who executes. Two teams cannot share one CR; nobody owns it and it stalls.
- **environment** — production and staging have different approval paths and different windows.
- **fix type** — `package_upgrade`, `image_rebuild`, `config_change`, `network_change`, `iam_change`. Different execution, different validation, different backout.
- **fix target** — the specific thing being changed: `openssl 3.0.11 → 3.0.14`, or the base image `acme/base:1.22 → 1.24`, or the control `S3 public access block`.

Worked cases:

| Upwind shows | Change groups | Why |
|---|---|---|
| One CVE, 40 containers, all from one base image, one team | **1** | One image rebuild fixes all forty. Forty CRs is forty times the CAB load for one change. |
| One CVE, 12 VMs, two teams | **2** | Each team executes their own; each needs their own window and backout. |
| Six CVEs, all fixed by the same base image bump | **1** | One change, six findings closed. List all six in the justification — this is the strongest CR you will write. |
| One CVE, one host, fix requires both a package upgrade and a config change | **2, linked** | Different validation and different backout. Sequence them and say which goes first. |
| A misconfiguration on 30 buckets in one account, one team | **1** | One policy change. Enumerate all thirty as affected CIs. |

The sentence to test a grouping against: *"one engineer, in one window, executing one plan, with one backout."* If that sentence is false, split it. If it is true for two of your CRs, merge them.

## Change class

| Class | When | Approval | Use for |
|---|---|---|---|
| **Emergency** | Active or imminent exploitation of a reachable asset | Emergency CAB, or retrospective approval per policy | Known-exploited CVE on an internet-exposed, running, in-use production workload; a misconfiguration exposing data right now |
| **Normal** | Everything consequential that can wait for the next CAB | Standard CAB, scheduled window | The overwhelming majority of production remediation |
| **Standard** | A pre-approved template in the change catalogue, executed before, with a known backout | No CAB; pre-authorized | Routine patching in non-production; catalogue-listed package upgrades; agent version bumps |

Two rules that keep this honest:

- **Emergency is not "severity: critical".** It is "exploitation is happening or is imminent *against this asset*". A critical CVE on an internal workload with no exposure and no known exploit is a normal change. Classify by exposure and exploitation, never by the score alone. Inflating to emergency to move faster is how emergency change stops meaning anything, and it is visible in the metrics within a quarter.
- **Standard requires the template to already exist.** If the change catalogue does not list it, it is normal, however routine it feels. "We always do this" is not a pre-approval.

## What CAB will ask, so answer it first

Every one of these belongs in the CR before anyone asks:

1. **Why now?** The exposure and exploitation evidence, not the CVSS. "Internet-exposed, code path observed loaded, EPSS 0.71, exploit in CISA KEV since March."
2. **What breaks?** The observed dependents, from Upwind's runtime graph. "Named by four internal services; no external consumers observed."
3. **How do you know it worked?** The validation step, runnable by the executor. A version assertion plus a service health check.
4. **How do you get back?** The backout, and its cost. "Redeploy previous image tag `1.22`, ~4 min, no data migration." A backout with a data migration in it is not a backout; say so and plan a forward fix.
5. **What if we do nothing?** The risk acceptance path, with an owner and an expiry. The SOC never accepts the risk; the system owner does.
6. **Who is affected and when?** The window, the expected impact, and whether a restart or failover is involved.

A CR missing any of these comes back, and the round trip costs more than writing it did.

## Cherwell field map

`scripts/cherwell_cr.py` writes these. **Field names and IDs vary by instance** — Cherwell business objects are customized per deployment, so verify yours against `getbusinessobjecttemplate` for the Change Request business object before the first real submission, and put the result in a field-map JSON (`--field-map`). The defaults below are the common out-of-the-box names, not a guarantee about your instance.

| CR field | Filled from | Notes |
|---|---|---|
| `Title` | Change group summary | `<fix type>: <fix target> on <n> <asset kind> (<environment>)` |
| `Description` | Findings in the group | Every finding ID and CVE, so the CR closes them traceably |
| `Justification` | Exposure + exploitation evidence | The "why now" answer; the field CAB actually reads |
| `ChangeType` / `Class` | Class selection above | emergency / normal / standard |
| `Priority` / `Urgency` / `Impact` | Rounds priority + asset count | Impact from the number and criticality of affected CIs |
| `RequestedBy` | The analyst running rounds | Never the agent; a person owns the request |
| `OwnedByTeam` | Asset `owner_team` | The team that executes |
| `ConfigItems` | Affected assets | Enumerated, not summarized — CAB needs the list |
| `ImplementationPlan` | Fix type template | Concrete commands or steps, not "upgrade the package" |
| `ValidationPlan` | Fix type template | How the executor proves it worked |
| `BackoutPlan` | Fix type template | The single-step restore and its cost |
| `ScheduledStartDate` / `ScheduledEndDate` | Window | Emergency: next available. Normal: next standard window. |
| `RiskLevel` | Blast radius + environment | Drives the CAB path in most instances |
| `SecurityFindingRef` | Upwind finding IDs | Custom field in most instances; keep it even if you must put it in Description |

### API shape

Cherwell's REST API (`/CherwellAPI`): get a token from `/token` with `grant_type=password`, `client_id`, `username`, `password` — then `POST /api/V1/savebo` with the business object ID and a `fields` array of `{fieldId, name, value, dirty: true}`. `scripts/cherwell_cr.py --dry-run` prints exactly that payload without sending it, which is the right way to check your field map. It refuses to run without credentials rather than half-submitting.

Newer Ivanti-branded deployments keep this API surface but may sit behind a different base path; set it with `--base-url`.

## After the CR

The CR is not the end of the duty. Each shift:

- **Track open CRs against finding age.** A finding whose CR has sat in "awaiting approval" for three weeks is an unremediated finding with paperwork, and it should be reported as such — P4, escalating as it ages.
- **Close the loop.** When the change is implemented, confirm in Upwind that the finding actually cleared. Changes that were implemented but did not fix the finding are common, and nobody notices unless you check.
- **Never approve or advance your own CR.** Stop-list item 4.
