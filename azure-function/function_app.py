"""Timer-triggered Azure Function: submit forwarded phishing reports to Defender.

Everything of substance is in `runner.py`, which has no Azure imports and is
covered by tests. This file is the binding.

Timer triggers hold a storage lease, so only one instance fires at a time — which
matters here, because two concurrent runs against one mailbox would double-submit.
"""
import logging

import azure.functions as func
import runner

app = func.FunctionApp()


@app.timer_trigger(schedule="0 */15 * * * *", arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def submit_reported_phish(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("Timer is past due; running now.")
    try:
        runner.run_once(log=logging.info)
    except runner.ConfigError as exc:
        # A misconfigured deployment should be loud and should not retry into a
        # tight loop, so this is logged as an error and the firing ends.
        logging.error("Configuration problem, nothing ran: %s", exc)
        raise
