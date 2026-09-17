# Rounds report formats

## Full rounds report

The analyst reads sections 1–3 every time and the rest only when they need it. Order by priority, never by portal.

```markdown
# SOC rounds — <date>, <window start> to <window end>
Operator: <name> · Sources: <which of the four were reachable>

## 1. Summary

| Source | In window | Needs a person | Handled automatically | Not collected |
|---|---|---|---|---|
| GitHub secrets | 14 | 3 | 9 closed as inactive | — |
| Upwind | 212 | 4 change groups | 186 below threshold | — |
| Defender | 23 | 5 | 16 auto-remediated | — |
| Sentinel | 11 | 2 | — | — |
| **After dedupe** | | **14 items** | | |

<n> Defender incidents were also present in Sentinel and are counted once.

**Collection gaps:** <every source that failed, and what the gap hides.
Say this even when there are none — "all four sources reachable" is a finding.>

## 2. Act now (P1)

| # | Source | Item | Why P1 | Action taken / needed | Owner |
|---|---|---|---|---|---|
| 1 | GitHub | Active AWS key, public repo, 3 locations | Validity active, public since 04:12 | **Revoked 09:20** — rollback: re-issue in IAM, acme-platform | done |
| 2 | Defender | INC-4471 credential theft, j.ruiz | Successful sign-in + mailbox rule created | Sessions revoked, account disabled 09:24 | IAM to confirm |

## 3. Needs your decision

Each item: what it is, what stopped it, and the decision that is being asked for.

**<item> — <tier> action blocked at <gate>**
- Evidence: <what you established>
- Not established: <what the gate needs>
- Recommended: <the action, precisely>
- Owner: <name or team>

## 4. Actions taken this round

Everything executed, with its undo. This is the section the next shift inherits.

| Time | Tier | Action | Target | Gates | Rollback |
|---|---|---|---|---|---|
| 09:20 | 2 | Revoke credential | AKIA…7Q2 | 1–5 pass, scope 2 | Re-issue in IAM, acme-platform |
| 09:31 | 1 | CR raised CHG-00918 | prod image acme/base:1.24 | n/a | Cancel CR |

## 5. Change requests

| CR | Class | Change group | Findings closed | Window | Status |
|---|---|---|---|---|---|
| CHG-00918 | Normal | image_rebuild acme/base 1.22→1.24, platform, prod | 6 | Thu 22:00 | Awaiting CAB |

Include for each: why this class, and the answers to the six CAB questions
(`references/upwind-cr.md`). Drafts not yet submitted are listed here too, marked DRAFT.

## 6. Worked and closed

Counts plus a line for anything notable. Do not re-litigate items automation closed.

## 7. Hygiene and gaps (P4)

Process findings: push-protection bypasses, incidents closed without classification,
noisy analytics rules, silent connectors, CRs aging in approval, out-of-scope
findings needing escalation. Each with a count and a named next step.

## 8. Carried forward

What the next shift inherits, and what it is waiting on.
```

## Single-item format

For "is this key live?", "what do I do with INC-4471?", "should this be a CR?" — skip the shift structure:

```markdown
**<item ID> — <one-line what it is>**

- **Priority:** P<n> — <the reason, in one clause>
- **Evidence:** <what you established, first-party sources named>
- **Not established:** <what you could not verify, and where it lives>
- **Action:** <the action, its tier, and whether the gates hold>
- **If blocked:** <the failed gate and what would clear it>
- **Owner:** <who decides>
```

## Writing rules

- **Lead with consequence, not with severity.** "Key is live and public" beats "Critical".
- **Name what you could not verify.** An analyst can act on a stated gap; they cannot act on a confident sentence that turns out to be an assumption.
- **Every stopped action names its failed gate.** "Needs review" tells the next person nothing. "Blocked at Gate 3: cannot enumerate consumers of this key" tells them exactly what to go and do.
- **Every recommendation names an owner.** A team or a role, not "someone".
- **Never report an uncollected source as zero.** Absent and clean look the same in a table and mean opposite things.
- **Counts before prose.** The summary table is what gets pasted into the ops channel.
