# Defender and Sentinel rounds

## The dedupe rule, first

Do this before anything else, because every count you produce afterwards is wrong otherwise.

When Microsoft Defender XDR is connected to Microsoft Sentinel, Defender incidents are **re-ingested into Sentinel**. The same attack appears in both queues with different IDs, and two analysts can independently work it for an hour without discovering each other.

A Sentinel incident is the same incident as a Defender one when any of these hold:

- it carries the Defender incident ID in `defender_incident_id` (or in the provider incident-ID field the connector populates)
- the two share one or more provider alert IDs
- the two share the same principal entity set and an overlapping activity window, and the Sentinel analytics rule is the Defender connector rule rather than a custom rule

Merge them into one item and record **which portal owns the response**:

| Situation | Owner | Why |
|---|---|---|
| Incident originated in Defender, synced to Sentinel | **Defender** | The response actions (isolate, revoke, AIR approvals) live there; Sentinel's copy is a view |
| Incident from a custom Sentinel analytics rule | **Sentinel** | No Defender counterpart exists to act in |
| Correlated: Defender alerts plus non-Microsoft signals joined by a Sentinel rule | **Sentinel** for the case, **Defender** for the endpoint/identity actions | Say both, explicitly, so neither half is dropped |

Bidirectional sync means a status change in the owning portal propagates. Closing the non-owning copy by hand creates a divergence someone will trust later. Close in the owner.

## The Defender walk

Order: **pending actions → unassigned high/critical → aging → everything else.**

### Pending AIR actions first

Automated investigation frequently stops with actions awaiting approval, and that queue is where response time is actually lost. For each:

- What is the action (soft delete, quarantine, isolate, block, kill process)?
- What is its blast radius (how many mailboxes, devices, users)?
- Does the evidence support it, independently of the investigation's own confidence?

Approving a pending AIR action is Tier 1 to Tier 2 depending on what it does: approving a quarantine of three messages is bookkeeping; approving a purge across four hundred mailboxes is containment with a large blast radius, and Gate 3 decides. Rejecting is the same in reverse — a rejection that lets an active payload sit in inboxes is an action too, and it needs the same justification.

An AIR that **failed or timed out** is not a verdict. It is a gap, and the item reverts to manual analysis at its underlying severity.

### Then the queue

For each incident gather: severity and the alerts behind it, impacted assets and identities, the MITRE technique, first and last activity, current status and assignment, and what automation has already done.

Escalate to **P1** when the evidence is of *live consequence* rather than of an attempt:

- an identity signed in successfully from an impossible or hostile location, and did something afterwards
- a device beaconing to known infrastructure, or a hands-on-keyboard pattern
- credential-theft tooling executed, not merely blocked
- lateral movement or privilege escalation observed
- data staged or moved

"Blocked" and "prevented" are P3 unless there are many of them or the same principal appears repeatedly — a blocked attempt is mostly information about the attacker's interest, and the pattern matters more than the instance.

### SLA clocks

Measure from **first activity**, not from when you opened the queue. An incident that fired at 02:00 and is unassigned at 09:00 is seven hours old regardless of when your shift started. Breaching an SLA promotes priority by one level and gets a line in the report — SLA breaches that are never reported are how a response-time problem stays invisible for a quarter.

Default clocks, to be overridden with the org's own:

| Severity | Acknowledge | Contain |
|---|---|---|
| Critical | 15 min | 1 h |
| High | 1 h | 4 h |
| Medium | 8 h | 24 h |
| Low | 24 h | best effort |

## The Sentinel walk

After dedupe, what remains is Sentinel's own: custom analytics rules, and correlations across sources Defender cannot see (network, SaaS, OT, on-prem applications, third-party logs).

Three questions per incident:

1. **Is the rule any good?** An incident from a rule that has fired forty times this month and closed benign forty times is a tuning finding (P4, Tier 3 — a CR, because rule changes are production changes), not an incident. Report the pattern; never quietly mute the rule.
2. **What did the correlation add?** The value of a Sentinel case is usually the join — a Defender identity alert plus firewall egress plus a SaaS download. Say what the join showed, because that is the part no other portal has.
3. **Are the entities mapped?** An incident whose entities did not map is a rule defect: it cannot be correlated, enriched, or acted on. P4, and worth fixing because it silently degrades everything downstream.

## Classification hygiene

Every incident you close gets a classification and a determination. No exceptions, and this is on the stop-list for a reason: closures are the training data for tuning, for detection coverage metrics, and for the next analyst's judgment about whether this rule ever matters.

- **True positive** — with the determination (malware, phishing, compromised account, malicious user activity, security testing)
- **Benign positive** — the activity happened and was authorized; say by whom, because "benign" with no owner named is how authorized-looking attacker activity gets closed
- **False positive** — the activity did not happen as described; say which part the rule got wrong, so the rule can be fixed

Closing an incident you did not investigate, to clear a queue, is worse than leaving it open. An open incident is visible; a wrongly-closed one is not.

## Hygiene items worth a P4 line every shift

- Incidents closed in the last window with no classification or no determination
- Analytics rules with a high benign-positive rate, named, with counts
- Incidents with unmapped entities
- Connectors not ingesting — a silent connector is indistinguishable from a quiet environment, and this is the check that separates them
- Devices or identities appearing in repeat incidents across shifts; the pattern is the finding
