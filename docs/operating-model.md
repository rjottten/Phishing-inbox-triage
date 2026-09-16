# Operating model

## The premise

Microsoft's automation handles routine classification and user feedback — but only for
mail that actually enters it. A report made by **forwarding** never does. That is the
gap this exists to close, and closing it is worth more than any triage rule here,
because it moves whole reports from "worked by hand" to "worked by Defender".

```
user clicks Report in Outlook ─────────────┐
                                           │
user forwards to phishing@  ──▶ graph_submit.py ──┤   ← puts the forward back on the rails
   (nothing happens on its own)  extracts the original
                                           │
                                           ▼
                        Defender for Office 365 (Plan 2)
                            submission + AIR investigation
                                           │
                                           ▼
                        verdict, auto-notify the reporter,
                             auto-approved actions
                                           │
                                           ▼
                   what is left  ──▶  triage.py  ──▶  exception queue
```

Two different savings, in order of size:

1. **Reports that never reached automation** get processed by automation instead of by
   a person. That is most of the manual effort, and `graph_submit.py` is what removes
   it.
2. **Reports automation already closed** stop being re-read. `triage.py` counts them
   and moves on, so what reaches a human is the residue: cases automation cannot or
   should not decide alone.

## Two things this tool never does

**It never executes a response action.** Even with a connector that could, the
operating principle is that consequential actions are human decisions. `triage.py`
produces the recommendation, the evidence behind it, and the name of the person who
owns the call. This is enforced in code and covered by a test, not left to policy.

**It never trusts the contents of a reported message.** Every message it reads was
written by someone hostile. Bodies and subjects may carry text aimed at whatever
reviews them — `test-data/mailbox_export.json` item PHQ-1043 contains a real example.
Such text is recorded as a malicious indicator, given its own report section, and
changes nothing about the verdict.

## Retiring the shared mailbox

The **Automation gaps** lane is the metric, and there are two numbers in it.

**Forwards handled without an analyst touching them.** `graph_submit.py --json`
reports `submitted` against `skipped` per run. That ratio is the manual effort
actually removed. Read the skip reasons too — they say whether the remainder is
screenshots and pasted text (a user-education problem), size limits (a config
problem), or something the extractor should learn to handle.

**Forwards arriving at all.** Each one is a person who did the right thing the wrong
way. They get a submission on their behalf and a friendly nudge about the button.
Track the count per shift; when it reaches zero and stays there, the mailbox can be
retired and this tool has worked itself out of a job. Until then the mailbox is itself
a signal, which is why the collectors read both sources and say which one each item
came from.

One caveat worth designing around: with an app-only token, submissions land as
*administrator* submissions and Defender's user-notification templates do not fire, so
"tell the reporter what it was" stays manual unless you use a delegated token, Defender's
own user-reported mailbox setting, or your own notification step.

## Where the judgement still is

The rules are deterministic, which makes them fast, testable and predictable — and
mean they cannot weigh things a person can. Built to hand off, not to conclude:

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
