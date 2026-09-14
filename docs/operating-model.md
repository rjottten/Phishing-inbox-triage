# Operating model

## The premise

Microsoft's automation handles routine classification and user feedback. Analysts
handle exceptions and consequential response actions. This tool exists to make the
analyst's queue as short and as well-evidenced as possible — not to re-triage
everything.

```
user clicks Report in Outlook
        │
        ▼
Defender for Office 365 (Plan 2)  ──▶  submission + AIR investigation
        │                                        │
        │                                        ▼
        │                              verdict, auto-notify the reporter,
        │                              auto-approved actions
        ▼
Security Copilot Phishing Triage Agent classifies the report
        │
        ▼
   what is left  ──▶  phish-triage  ──▶  exception queue for a human
```

What reaches a human should be the residue: cases automation cannot or should not
decide alone.

## Two things this tool never does

**It never executes a response action.** Even with a connector that could, the
operating principle is that consequential actions are human decisions. The engine
produces the recommendation, the evidence behind it, and the name of the person who
owns the call. This is enforced in code and covered by a test, not left to policy.

**It never trusts the contents of a reported message.** Every message it reads was
written by someone hostile. Bodies and subjects may carry text aimed at whatever
reviews them — `test-data/mailbox_export.json` item PHQ-1043 contains a real example.
Such text is recorded as a malicious indicator, given its own report section, and
changes nothing about the verdict.

## Retiring the shared mailbox

The **Automation gaps** lane is the metric. Anything arriving in the shared mailbox
instead of through the Report button did not enter the pipeline: no submission, no
AIR, no notification to the reporter. Each one gets a submission on the user's behalf
and a friendly nudge about the button — they did the right thing by reporting.

Track the count per shift. When it reaches zero and stays there, the mailbox can be
retired. Until then, the mailbox is itself a signal, which is why the tool reads both
sources and says which one each item came from.

## Where the judgement still is

The engine is deterministic, which makes it fast, testable and predictable — and
means it cannot weigh things a person can. It is built to hand off, not to conclude:

- The **exceptions table** is a worklist, not a set of verdicts.
- **Not verified** lists what could not be confirmed and where to look. Read it
  before acting on the evidence above it.
- **Open questions** are the ones whose answers change the priority — most often
  "did they enter credentials after clicking?"

For the cases where a person wants the reasoning rather than the table — one pasted
email, an odd verdict, a judgement call about scope — the Claude skill in `skills/`
covers the same ground in prose. See [`skills/README.md`](../skills/README.md).

## A note on tuning

If you find yourself disagreeing with the AIR verdict on most items, the tool
reports that in the trends section on purpose. It is not a finding about those
messages; it is a finding about the tenant's configuration.
