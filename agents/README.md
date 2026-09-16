# The model-assisted layer

Everything in `skills/phishing-inbox-triage/scripts/` is stdlib-only, offline, and
runs from a checkout with nothing installed. **These do not.** They need
`pip install -r agents/requirements.txt`, an `ANTHROPIC_API_KEY`, and network egress
from a machine that reads reported mail — which is why they live here rather than in
the skill bundle, and why a test fails the build if one moves in.

Use them for the work deterministic code provably cannot do. Not as a replacement
for the rules.

| | |
|---|---|
| `resolve_worklist.py` | Reads the forwards `graph_submit.py` could not parse — screenshots, pasted text, inline forwards — and proposes the original email's details as export items `triage.py` can route. |

## The design rule

> **The component that reads hostile content holds no tools and makes no decisions.**

Reported mail is attacker-controlled by construction. The rest of this repository
keeps that cheap: `triage.py` and `parse_headers.py` read hostile bodies but import
nothing network-capable, so text aimed at an automated reviewer is inert. Put a model
in that seat *with tools* and you have assembled the thing worth worrying about —
untrusted input, sensitive data, and the ability to act.

So the split is:

- **The model proposes facts.** `resolve_worklist.py`'s output schema has no verdict,
  lane, priority or action field. There is nothing for it to set even when a reported
  message asks it to, and a test asserts that for every decision word.
- **The rules decide.** Extracted items go through `triage.py` exactly like any other
  item, scored by the same rules, auditable the same way.
- **A person acts.** Nothing here submits, purges, blocks, replies, or clears a
  worklist entry.

Defence is layered, because a prompt instruction alone is not a control:

1. The system prompt states the content is hostile evidence, not instruction.
2. The structured-output schema gives the model no decision field to fill.
3. Everything that comes back is re-validated before it can reach the queue: URLs
   defanged unconditionally, fields length-capped, control characters stripped,
   anything shaped wrongly dropped and named, unknown fields a hard failure.
4. Unrecognised values fail *toward* "a person should look at this" — an unreadable
   confidence becomes `low`, never `high`.

## What leaves your tenant

`resolve_worklist.py` sends the **body and image attachments** of messages already on
the worklist to the Claude API. That is a real widening: `graph_submit.py` asks Graph
for eight fields and never downloads a body at all.

It is scoped to reports that already failed automated extraction, and `--dry-run`
shows you exactly what would be sent without calling the model. If mail content cannot
leave your boundary, do not use this — `SKILL.md` is plain markdown and runs against
an in-tenant deployment instead.

## resolve_worklist.py

```bash
pip install -r agents/requirements.txt
export ANTHROPIC_API_KEY=...
export GRAPH_TENANT_ID=... GRAPH_CLIENT_ID=... GRAPH_CLIENT_SECRET=...

# see what would be sent, call nothing
python agents/resolve_worklist.py --worklist worklist.json \
    --mailbox phishing@contoso.com --dry-run

python agents/resolve_worklist.py --worklist worklist.json \
    --mailbox phishing@contoso.com --out proposed.json

python skills/phishing-inbox-triage/scripts/triage.py proposed.json \
    --org-context org-context.json
```

It works `no_original_attached` entries only. `too_large` and
`no_recipient_resolved` have deterministic fixes — a raised `--max-eml-bytes`, an
added `--org-domain` — and a model guessing at them would paper over a config problem
rather than surface it. `--reason` overrides that if you want it.

**Every item it emits is a proposal.** Each carries an `extraction` block naming the
model's confidence and what it could not read, `defender` is `null` because nothing
has been submitted, and the export's `collection_notes` say plainly that
authentication results are absent — you cannot read SPF off a screenshot, so BEC
scoring is weaker on this path. The worklist entry stays open: the report still has
not reached Defender.

## Testing

`tests/test_agents.py` runs offline with no SDK and no key — `anthropic` is imported
lazily, so every pure function is covered and the model call is driven through a
recorder. The weight is on validation, because that layer is the safety argument.
