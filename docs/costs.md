# What this costs to run

For whoever approves the spend. Written so the arithmetic is visible and you can
redo it with your own numbers rather than trusting mine.

Three categories: **Microsoft licensing** (probably already paid for, but worth
confirming), **Azure hosting** (small enough to be a rounding error), and the
**Anthropic API** (optional, and the only line item that scales with volume).

## Summary

| Item | Cost | Notes |
|---|---|---|
| This repository | **£0** | Stdlib Python, no dependencies, no licence |
| Microsoft Graph API calls | **£0** | Included with M365. Throttled, not billed |
| Defender for Office 365 **Plan 2** | **Already paid, or a blocker** | Needed for AIR and Advanced Hunting. See below |
| Azure Function (Consumption) | **≈£0** | Free grant covers this workload ~350× over |
| Azure Storage account | **A few pence/month** | You hit the account minimum before the data matters |
| Application Insights | **≈£0** | Free tier is 5 GB/month; this logs a few lines per run |
| `agents/resolve_worklist.py` | **Optional, ~£0.03–0.08/report** | Only if you deploy it. Worked example below |
| Admin time to deploy | **~2–4 hours, one-off** | Across three people. See below |

**If you never deploy the optional model layer, the recurring cost is under a pound
a month**, assuming you already have Defender Plan 2.

## The free path

The whole deterministic route costs nothing and needs nothing granted:

```
portal CSV export → import_defender_csv.py → triage.py → a report
```

No app registration, no consent, no Azure, no network calls at all. This is how to
prove the thing works before anyone spends anything. Treat it as the evaluation.

## 1. Microsoft licensing — the one that could actually block you

Graph itself is free to call. The question is what your Defender tier gives you.

| Capability | Requires |
|---|---|
| Creating submissions | Broadly available, including EOP |
| **AIR** — the investigation that produces a verdict | **Defender for Office 365 Plan 2** |
| **Advanced Hunting** — `UrlClickEvents`, `EmailEvents` | **Plan 2**, or Defender XDR |
| Safe Links / Safe Attachments | Plan 1 and above |

**This matters more than any number in this document.** On Plan 1 or plain EOP,
`graph_submit.py` still submits, but no AIR investigation runs — so no verdict comes
back, and `triage.py` has nothing to route on. The entire operating model assumes
Plan 2.

Check **Defender portal → Settings**, or ask whoever owns your M365 licences, before
budgeting anything else. Per-seat pricing depends on your agreement, so it is not
quoted here — if you already have Plan 2, this line is £0 and nothing changes.

## 2. Azure hosting

Only applies if you use `azure-function/`. Running it on a host you already have
with cron costs nothing extra.

**Azure Functions, Consumption plan.** The free grant is 1,000,000 executions and
400,000 GB-seconds per month, per subscription.

```
every 15 minutes = 4/hour × 24 × 30  =  2,880 executions/month
                                        ~0.3% of the free grant
```

Each run is a few seconds and a few hundred MB, so GB-seconds are similarly
negligible. **This workload does not leave the free tier.**

**Storage account.** Required by Functions, and where `state.json` and
`worklist.json` live. Both are small JSON files; the state ledger grows by one short
entry per handled message. Standard LRS hot storage is roughly £0.02/GB/month plus
per-operation costs measured in fractions of a penny at this volume. **In practice
you are paying for the account to exist, not for what is in it.**

**Application Insights.** The free tier includes 5 GB/month of ingestion. This logs
a handful of lines per run — counts, statuses, subjects. Nowhere near it.

Realistic total: **well under £1/month**, and plausibly zero if the storage account
is shared with something else. Confirm against the
[Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your
region before committing to a figure.

## 3. The Anthropic API — optional, and the only thing that scales

This applies **only** if you deploy `agents/resolve_worklist.py`, the component that
reads screenshots and pasted-in forwards. It is not part of the scheduled
deployment, and nothing else in the repository calls it.

Pricing for Claude Opus 5 is **$5 per million input tokens and $25 per million
output tokens** (from the SDK reference, cached 2026-06-24 — confirm against
[current pricing](https://www.anthropic.com/pricing) before budgeting).

### Worked example, assumptions visible

Per report resolved:

| Component | Estimate |
|---|---|
| System prompt | ~450 tokens |
| Context header | ~100 tokens |
| Forward body (capped at 20,000 chars) | ~150–5,000 tokens |
| One screenshot, if present | ~1,500 tokens |
| **Input subtotal** | **~700–7,000 tokens** |
| Structured extraction out | ~300–600 tokens |
| Adaptive thinking (billed as output) | ~500–2,000 tokens |
| **Output subtotal** | **~800–2,600 tokens** |

At Opus 5 rates, a mid-case report — 5,000 in, 1,500 out — costs:

```
input   5,000 / 1,000,000 × $5   = $0.025
output  1,500 / 1,000,000 × $25  = $0.0375
                                   ───────
                            total ≈ $0.06 per report
```

Scaled:

| Unparseable reports | Monthly cost |
|---|---|
| 20/week (~87/month) | **~$5** |
| 50/week (~217/month) | **~$13** |
| 100/week (~434/month) | **~$26** |

**These are estimates, not measurements.** The honest way to get a real figure is the
dry run: `graph_submit.py --dry-run --json --worklist` tells you how many reports
actually fall into this bucket, which is the multiplier. Everything above is
arithmetic on a number nobody has measured yet.

### Levers, if volume ever made it material

- **Only unparseable reports reach it.** It works `no_original_attached` entries
  only; everything `graph_submit.py` handles cleanly never touches the API.
- **Fixing the upstream cause removes the cost entirely.** Most of this bucket is
  users pasting or screenshotting instead of attaching. Coaching, or Defender's
  native user-reported setting, shrinks the input.
- **A cheaper model is available** — Sonnet 5 at $2/$10 per MTok, Haiku 4.5 at
  $1/$5. Whether extraction quality holds at a lower tier is a judgement about your
  data, not one I can make for you; `--model` takes any of them if you want to
  measure it.

## 4. One-off effort

Not a bill, but the real cost of getting started:

| Task | Who | Rough time |
|---|---|---|
| Check Defender's native user-reported setting | Security admin | 10 min |
| App registration, permissions, consent | Entra ID admin | 30 min |
| Scope `Mail.Read` to the one mailbox | Exchange admin | 30 min |
| Deploy the Function and configure it | Azure owner | 30–60 min |
| Read a dry run and verify the output | Whoever owns the queue | 30 min |

**2–4 hours across three people**, most of it waiting for consent and scope
propagation (which can take an hour). `docs/deployment.md` is the runbook.

## 5. The number you are comparing against

The point of this project is to remove manual effort, so the comparison is your own
analyst time. I do not know your volume or rates, so here is the formula rather than
an invented figure:

```
forwarded reports per month
  × minutes an analyst currently spends per report
  × loaded hourly rate ÷ 60
  = what the manual process costs today
```

Per forwarded report an analyst currently: opens the forward, digs out the original,
submits it to Defender, waits, reads the verdict, decides, replies to the reporter,
and files the mail. Only the *deciding* genuinely needs a person.

Both inputs come from the same dry run. Do that before building a business case on
this — it costs nothing and sends nothing.

## Where these numbers could be wrong

- **Defender Plan 2 is assumed.** If you do not have it, the costs above are the
  wrong question and the licensing conversation is the real one.
- **Nothing has been run against a live tenant.** Volumes, throttling behaviour and
  the size of the unparseable bucket are all unmeasured.
- **Azure and Anthropic prices change**, and both vary by region or agreement. Both
  links above are the authority; this document is not.
- **The token estimates are reasoned, not observed.** A tenant whose users mostly
  send long screenshots will sit at the top of the range.
