"""What the timer actually does, with no Azure imports at module scope.

`function_app.py` is a four-line decorator shim over this. Keeping the logic here
means the whole of it — config validation, the argv it builds, the fail-closed
rules — is covered by `tests/test_azure_function.py` on a clean interpreter with
no azure packages and no credentials.

Two things this owns that a bare cron job would not have to:

**State has to outlive the instance.** A Function's local disk is ephemeral.
`graph_submit.py`'s state file is the watermark and the processed-message ledger;
lose it and the next run resubmits everything in the lookback window. So state
and the worklist live in blob storage and are round-tripped on each run.

**It fails closed.** No mailbox, no scope control, or a failed scope probe stops
the run. An unattended job holding `Mail.Read` is exactly the thing that should
refuse to start when it cannot prove what it can reach.
"""
import contextlib
import os
import sys

STATE_BLOB = "state.json"
WORKLIST_BLOB = "worklist.json"
DEFAULT_CONTAINER = "phish-triage"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

#: Where the shipped scripts are, deployed or in a checkout. `prepare.sh` copies
#: them into the function app; the second entry is for running from the repo.
SCRIPT_DIRS = (
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "skills", "phishing-inbox-triage", "scripts"),
)


class ConfigError(RuntimeError):
    """The app settings are missing or unsafe. The message names the setting."""


def truthy(value, default=False):
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def script_dir(candidates=SCRIPT_DIRS):
    for path in candidates:
        if os.path.isdir(path) and os.path.exists(os.path.join(path, "graph_submit.py")):
            return path
    raise ConfigError(
        "graph_submit.py was not found. Run azure-function/prepare.sh before "
        "deploying so the scripts ship with the function app. Looked in: {}".format(", ".join(candidates)))


def load_config(env):
    """Read and check the app settings. Raises rather than guessing.

    Every required setting here is required because getting it wrong is silent:
    no mailbox means nothing happens, no org domain means recipients cannot be
    resolved and every message skips, and no deny-check means the run cannot
    prove it is reading only the mailbox it should be.
    """
    mailbox = (env.get("PHISH_MAILBOX") or "").strip()
    if not mailbox:
        raise ConfigError("PHISH_MAILBOX is not set: which shared mailbox to watch")

    deny = [a.strip() for a in (env.get("PHISH_DENY_CHECK") or "").split(",") if a.strip()]
    if not deny:
        raise ConfigError(
            "PHISH_DENY_CHECK is not set. Name at least one mailbox this app must "
            "NOT be able to read (an exec's, say). Mail.Read is tenant-wide until "
            "Exchange scoping is applied, and a scope that never propagated looks "
            "exactly like one that works — this is how the run proves otherwise.")
    if mailbox.lower() in {a.lower() for a in deny}:
        raise ConfigError("PHISH_DENY_CHECK contains the mailbox being watched; "
                          "the run would abort on its own target")

    domains = [d.strip() for d in (env.get("PHISH_ORG_DOMAIN") or "").split(",") if d.strip()]
    if not domains:
        raise ConfigError("PHISH_ORG_DOMAIN is not set: your mail domain(s), so the "
                          "real recipient can be read out of the original")

    return {
        "mailbox": mailbox,
        "deny_check": deny,
        "org_domains": domains,
        # Live only when someone has explicitly said so. A deploy that starts
        # submitting to Defender before anyone has read a dry run is not a
        # deploy anybody wanted.
        "dry_run": not truthy(env.get("PHISH_DRY_RUN_OFF")),
        "mark_read": truthy(env.get("PHISH_MARK_READ")),
        "move_to": (env.get("PHISH_MOVE_TO") or "").strip(),
        "capture_note": truthy(env.get("PHISH_CAPTURE_REPORTER_NOTE")),
        "lookback_hours": int(env.get("PHISH_LOOKBACK_HOURS") or 24),
        "max_messages": int(env.get("PHISH_MAX") or 100),
        "container": (env.get("PHISH_STATE_CONTAINER") or DEFAULT_CONTAINER).strip(),
        "storage": env.get("AzureWebJobsStorage") or "",
    }


def build_argv(config, state_path, worklist_path):
    """The command line the timer runs. Kept as argv so what the Function does is
    exactly what an operator can reproduce by hand from the same settings."""
    argv = ["--mailbox", config["mailbox"],
            "--state", state_path,
            "--worklist", worklist_path,
            "--default-lookback-hours", str(config["lookback_hours"]),
            "--max", str(config["max_messages"]),
            "--dedupe-original",
            "--json"]
    for address in config["deny_check"]:
        argv += ["--deny-check", address]
    for domain in config["org_domains"]:
        argv += ["--org-domain", domain]
    if config["dry_run"]:
        argv.append("--dry-run")
    if config["mark_read"]:
        argv.append("--mark-read")
    if config["move_to"]:
        argv += ["--move-to", config["move_to"]]
    if config["capture_note"]:
        argv.append("--capture-reporter-note")
    return argv


def graph_token(scope=GRAPH_SCOPE):
    """A Graph token from the Function's managed identity.

    This is the reason to run it here rather than on a box with a cron job: there
    is no client secret to store, rotate, or leak.
    """
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential().get_token(scope).token


class BlobState:
    """Round-trips the state file and worklist through blob storage.

    Download before the run, upload after — including after a partial failure, so
    messages already submitted are never replayed.
    """

    def __init__(self, connection_string, container, work_dir):
        self.connection_string = connection_string
        self.container = container
        self.work_dir = work_dir
        self.state_path = os.path.join(work_dir, STATE_BLOB)
        self.worklist_path = os.path.join(work_dir, WORKLIST_BLOB)
        self._client = None

    def client(self):
        if self._client is None:
            from azure.storage.blob import BlobServiceClient
            service = BlobServiceClient.from_connection_string(self.connection_string)
            container = service.get_container_client(self.container)
            # Already-exists is the normal case after the first ever run.
            with contextlib.suppress(Exception):
                container.create_container()
            self._client = container
        return self._client

    def download(self):
        for name, path in ((STATE_BLOB, self.state_path),
                           (WORKLIST_BLOB, self.worklist_path)):
            try:
                data = self.client().get_blob_client(name).download_blob().readall()
            except Exception:  # noqa: BLE001 - absent on the first ever run
                continue
            with open(path, "wb") as fh:
                fh.write(data)

    def upload(self):
        for name, path in ((STATE_BLOB, self.state_path),
                           (WORKLIST_BLOB, self.worklist_path)):
            if not os.path.exists(path):
                continue
            with open(path, "rb") as fh:
                self.client().get_blob_client(name).upload_blob(fh, overwrite=True)


def summarise(worklist_path):
    """Counts only. Never subjects, senders, bodies or URLs — this goes to
    Application Insights, which is not where reported phishing content belongs."""
    import json
    if not os.path.exists(worklist_path):
        return 0
    try:
        with open(worklist_path, encoding="utf-8") as fh:
            return len(json.load(fh).get("open", {}))
    except (ValueError, OSError):
        return 0


def run_once(env=None, work_dir="/tmp", log=print):
    """One timer firing. Returns graph_submit's exit code."""
    env = os.environ if env is None else env
    config = load_config(env)

    scripts = script_dir()
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import graph_submit as gs

    state = BlobState(config["storage"], config["container"], work_dir)
    if config["storage"]:
        state.download()
    else:
        log("WARNING: AzureWebJobsStorage is unset, so state is not persisted. "
            "Every run will re-scan its whole lookback window.")

    env_token = env.get("GRAPH_ACCESS_TOKEN") or graph_token()
    previous = os.environ.get("GRAPH_ACCESS_TOKEN")
    os.environ["GRAPH_ACCESS_TOKEN"] = env_token
    argv = build_argv(config, state.state_path, state.worklist_path)
    log("Running graph_submit{} for {}".format(" (dry run)" if config["dry_run"] else "", config["mailbox"]))
    try:
        code = gs.main(argv)
    finally:
        if previous is None:
            os.environ.pop("GRAPH_ACCESS_TOKEN", None)
        else:
            os.environ["GRAPH_ACCESS_TOKEN"] = previous
        # Upload even on failure: a partial run has already submitted messages,
        # and losing that ledger is what causes duplicates.
        if config["storage"]:
            state.upload()

    log(f"Worklist: {summarise(state.worklist_path)} report(s) still need a person")
    if code == 3:
        raise RuntimeError(
            "scope check failed: this app can reach a mailbox it must not, or "
            "cannot reach the one it should. Refusing to continue.")
    if code == 2:
        raise RuntimeError("graph_submit run failed; see the logs above")
    if code == 1:
        log("Some messages errored; they stay on the worklist for the next run.")
    return code
