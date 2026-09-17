# GitHub secret scanning rounds

## What you are actually deciding

Not "is this a secret?" — GitHub's detectors are pattern-matched against provider-supplied signatures and their false-positive rate on *recognized* types is low. You are deciding three things:

1. **Is it live?** (validity)
2. **Who could have taken it?** (exposure)
3. **Can it be killed without taking a service down with it?** (blast radius — Gate 3)

Only the third one is hard, and it is the one that decides whether you revoke now or wake somebody up.

## Validity states, and what each one licenses

GitHub's validity check asks the provider whether the credential still authenticates. It runs for partner-verifiable types only.

| `validity` | Means | What it licenses |
|---|---|---|
| `active` | The provider confirmed it authenticates right now | First-party evidence. **Gate 1 passes.** |
| `inactive` | The provider confirmed it does not | Close as already-revoked, after confirming the revocation was deliberate and not just a rotation that left the old key in history |
| `unknown` | Not checkable, or the check failed | **Gate 1 fails.** Verify out-of-band or treat as live and escalate |

`unknown` is the common case, not the exception — most custom patterns, and every internal credential format, land here. An unknown-validity secret in a public repository is still a P1 *finding*; it is simply not an auto-revoke *action*, because you do not have first-party evidence. Go get it: check the provider console for last-used, or the cloud audit log for authentications from unexpected addresses.

**Inactive does not mean safe.** It means not usable now. If it was live for six days in a public repo, the incident is what happened during those six days, and that is a hunting question, not an alert-closing question.

## Exposure — who could have taken it

Rank by reachability, not by repository name:

1. **Public repository** — assume harvested. Credential-scraping bots find public commits in seconds to minutes, not hours. The clock started at push time, not at alert time.
2. **Public fork or a public gist** of a private repo — same as public. Check whether the alert's locations span repositories.
3. **Private repository, broad org access** — scoped to your org's members and any installed app with contents access. Count the actual population before calling it contained.
4. **Private repository, narrow access** — the smallest case, and the only one where "we have time" is a defensible sentence.

Two multipliers that change the answer:

- **Commit history.** Deleting the line does not remove the secret. It lives in the object store and in every clone and fork until the key is dead. Never accept "we removed it from the file" as remediation; the only remediation is revocation.
- **Location count.** One secret in nine files across three repos is not nine alerts — it is one credential with a distribution problem, and it tells you the same value is probably in a CI variable, a runbook, and somebody's laptop.

## Push protection bypasses

A bypass is a person choosing to commit a secret past a block, with a stated reason. Every bypass is worth reading, and the reason given is a hypothesis, not a fact:

- *"It's a test value"* — verify. Test fixtures with real credentials are how a large share of these start.
- *"It's already revoked"* — verify against validity. Revoked-later is not revoked-then.
- *"False positive"* — verify, then fix the detector or add the path exclusion so the next person is not trained to bypass.

A rising bypass count is a P4 process finding with a real security consequence: it means the control is being routed around, and the control was the thing standing between you and this file. Report the count and the top bypassing repositories every shift, even when each individual bypass was benign.

## Revoke and rotate, in the right order

Order matters, because doing it the intuitive way causes the outage:

1. **Enumerate consumers first** (Gate 3). What authenticates with this credential? Check the provider's last-used data, the cloud audit log, CI configuration, and the owning team. If you cannot enumerate, you cannot auto-revoke — escalate to the service owner with the finding already written up.
2. **Issue the replacement** before killing the original, wherever the provider supports two live credentials. This converts an outage into a deployment.
3. **Deploy the replacement** to every consumer you enumerated. Tier 3 if it means changing infrastructure configuration — which it usually does, so it usually means a CR.
4. **Revoke the original.** This is the Tier 2 action.
5. **Verify** with the provider that the old credential now fails, and that the new one is in use.
6. **Hunt** over the exposure window: authentications from unexpected addresses, regions, or user agents; resource creation; privilege changes; data egress. A revoked key with no hunt is half a response — the question is not only "is it dead" but "what did it do while alive".
7. **Close the alert with a resolution**, and only then. `revoked` when you killed it; `false_positive` only with evidence; `used_in_tests` only after confirming the value does not authenticate to anything real.

Where a provider supports no overlapping credentials, steps 2–4 collapse into a single cutover, and that cutover is a change with a window — a CR, not a Tier 2 action.

## Auto-revoke: when it actually passes the gates

It passes when all of these are true, and this combination is uncommon enough to be worth stating plainly:

- validity is `active` (Gate 1)
- exposure is public, or the secret is confirmed used from an address outside your estate (Gate 2 — no competing reading)
- consumers are enumerated and within the scope limit, **or** the credential is confirmed to have no consumers — a developer's personal token, an unused deploy key (Gate 3)
- the provider supports re-issuing the same scope (Gate 4)
- the rollback is written: which provider console, which scope, who re-issues (Gate 5)

The frequent failure is Gate 3 on a shared service credential. When it fails, the finding stays P1, the action becomes "service owner revokes within N hours", and you say so in the report with the owner named — you do not quietly downgrade the finding to match the action you were allowed to take.

## What secret scanning does not tell you

- **Whether it was used.** Only the provider's audit log knows. GitHub knows the secret exists and whether it authenticates — not what it did.
- **What it can reach.** An "active" key with `AdministratorAccess` and an active key with read on one bucket look identical in the alert list. Scope comes from the provider.
- **Secrets it has no detector for.** Internal token formats, database connection strings in unusual shapes, and private keys in unusual encodings pass through silently. A clean queue is evidence about the detectors, not about the repositories.
- **Whether the commit author is the owner.** The person who pushed it often is not the person who can revoke it. Route by CODEOWNERS and the service's owning team, not by commit authorship.

## Hygiene items worth a P4 line every shift

- Repositories in scope with secret scanning or push protection off — name them
- Bypass count and the top bypassing repositories
- Alerts open past the SLA, by age bucket
- Alerts closed as `false_positive` or `used_in_tests` with no evidence recorded — a QA sample of three per shift is enough to keep this honest
