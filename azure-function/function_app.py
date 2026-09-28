"""Azure Functions entry points for phishing-inbox-triage (Python v2 model).

Two timer-triggered functions. Everything they do is in runner.py; this file
only binds schedules to it.

  submit_forwarded_reports  PHISH_SUBMIT_SCHEDULE  graph_submit.py: forwarded
                                                   reports -> Defender submissions
  collect_and_triage        PHISH_TRIAGE_SCHEDULE  collect_export.py + triage.py:
                                                   queue -> handover report in Blob

Turn the second off with the app setting
AzureWebJobs.collect_and_triage.Disabled=true if you only want submissions.

Timer triggers run as singletons across instances, which graph_submit.py
relies on: its state is not locked, and two concurrent runs would
double-submit.
"""
import logging

import azure.functions as func

import runner

app = func.FunctionApp()


@app.timer_trigger(schedule="%PHISH_SUBMIT_SCHEDULE%", arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def submit_forwarded_reports(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("submit_forwarded_reports is running late")
    counts = runner.run_submit()
    logging.info("submit_forwarded_reports done: %s", counts)


@app.timer_trigger(schedule="%PHISH_TRIAGE_SCHEDULE%", arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def collect_and_triage(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("collect_and_triage is running late")
    outcome = runner.run_triage()
    logging.info("collect_and_triage done: %s", outcome)
