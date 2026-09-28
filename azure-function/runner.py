"""What the Azure Functions in function_app.py actually do.

Kept apart from function_app.py so it imports without the Functions runtime and
can be tested offline: the Azure SDKs are only imported inside the two classes
that need them, and the tests replace both.

The scripts are run as they are, through their own ``main(argv)``. Nothing here
re-implements what they do; this module only supplies what a Function App
lacks and a shell has:

* **Configuration.** The scripts take command-line flags. Here those come from
  ``PHISH_*`` app settings, mapped in ``submit_argv`` / ``collect_argv`` /
  ``triage_argv``.
* **Credentials.** A managed-identity token is fetched per run and handed over
  in ``GRAPH_ACCESS_TOKEN``; a static token in app settings would expire.
* **Durable state.** ``graph_submit.py --state`` is a local file, and local disk
  in a Function does not survive. The state lives in Blob storage and is
  written back with an ETag condition, so a lost update fails loudly instead of
  silently allowing a resubmission.
* **Failure you can see.** The scripts return exit codes. A non-zero code is
  raised here, so the invocation shows as failed in Application Insights and
  can be alerted on. Exit 3 (the mailbox scope check failed) has its own type.
"""
import contextlib
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def _scripts_dir():
    """``scripts/`` in the deployed package, or the repo's copy in a checkout."""
    for candidate in (os.path.join(HERE, "scripts"),
                      os.path.join(os.path.dirname(HERE), "phishing-inbox-triage", "scripts")):
        if os.path.isfile(os.path.join(candidate, "graph_submit.py")):
            return candidate
    raise ImportError("graph_submit.py not found next to runner.py; build the package "
                      "with package.sh rather than deploying this folder directly")


sys.path.insert(0, _scripts_dir())

import collect_export  # noqa: E402
import graph_submit    # noqa: E402
import triage          # noqa: E402

log = logging.getLogger("phish_triage")

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFAULT_CONTAINER = "phish-triage"
DEFAULT_STATE_BLOB = "state/graph_submit_state.json"

# One job at a time per worker process. The scripts log to sys.stderr and the
# wrapper borrows sys.stdout and os.environ for the length of a run, all of
# which are process-wide; two overlapping invocations would mix each other's
# logs and credentials. Across instances, timer triggers are already singletons.
_RUN_LOCK = threading.Lock()


class ConfigError(RuntimeError):
    """An app setting is missing or wrong. Nothing was read or sent."""


class RunFailed(RuntimeError):
    """A script finished with a non-zero exit code."""

    def __init__(self, message, exit_code=None):
        super().__init__(message)
        self.exit_code = exit_code


class ScopeCheckFailed(RunFailed):
    """Exit 3: this app can read a mailbox it must not, or cannot read its own."""


class StateConflict(RuntimeError):
    """The state blob changed underneath this run."""


# --------------------------------------------------------------------------
# App settings
# --------------------------------------------------------------------------

def _setting(env, name, default=None):
    value = env.get(name)
    if value is None or not str(value).strip():
        return default
    return str(value).strip()


def _flag(env, name, default=False):
    value = _setting(env, name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError("%s must be true or false, got %r" % (name, value))


def _number(env, name, default):
    value = _setting(env, name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigError("%s must be a whole number, got %r" % (name, value))


def _addresses(env, name):
    """Comma- or semicolon-separated list, blanks dropped."""
    value = _setting(env, name, "")
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def _mailbox(env):
    mailbox = _setting(env, "PHISH_MAILBOX")
    if not mailbox:
        raise ConfigError("PHISH_MAILBOX is not set: the shared phishing mailbox to watch")
    return mailbox


def _deny_checks(env):
    """Control mailboxes for the scope probe. Required unless explicitly waived.

    Mail.Read as an application permission reaches every mailbox in the tenant
    unless an Exchange scope narrows it, and that narrowing is invisible from
    here. Without a control mailbox the run cannot tell the difference, so the
    default is to refuse rather than run unverified on a schedule.
    """
    deny = _addresses(env, "PHISH_DENY_CHECK")
    if not deny and not _flag(env, "PHISH_ALLOW_UNVERIFIED_SCOPE"):
        raise ConfigError(
            "PHISH_DENY_CHECK is not set. Name at least one mailbox this app must NOT "
            "be able to read (an executive's, payroll); every run proves it gets a 403 "
            "before reading any mail. Set PHISH_ALLOW_UNVERIFIED_SCOPE=true to run "
            "without that proof.")
    return deny


def submit_argv(env, state_path):
    """graph_submit.py flags for the scheduled submission run."""
    argv = ["--mailbox", _mailbox(env),
            "--folder", _setting(env, "PHISH_FOLDER", "inbox"),
            "--category", _setting(env, "PHISH_CATEGORY", "phishing"),
            "--max", str(_number(env, "PHISH_MAX", 100)),
            "--default-lookback-hours", str(_number(env, "PHISH_DEFAULT_LOOKBACK_HOURS", 24)),
            "--json"]
    if state_path:
        argv += ["--state", state_path]
    for domain in _addresses(env, "PHISH_ORG_DOMAINS"):
        argv += ["--org-domain", domain]
    for address in _deny_checks(env):
        argv += ["--deny-check", address]
    if _flag(env, "PHISH_DEDUPE_ORIGINAL", True):
        argv.append("--dedupe-original")
    if _flag(env, "PHISH_CAPTURE_REPORTER_NOTE"):
        argv.append("--capture-reporter-note")
    if _flag(env, "PHISH_MARK_READ"):
        argv.append("--mark-read")
    move_to = _setting(env, "PHISH_MOVE_TO")
    if move_to:
        argv += ["--move-to", move_to]
    source = _setting(env, "PHISH_SOURCE")
    if source:
        argv += ["--source", source]
    api_version = _setting(env, "PHISH_API_VERSION")
    if api_version:
        argv += ["--api-version", api_version]
    if _flag(env, "PHISH_DRY_RUN"):
        argv.append("--dry-run")
    return argv


def collect_argv(env, export_path, org_context_path=None, notes_path=None):
    """collect_export.py flags. Minimal extraction (no mailbox read) by default."""
    argv = ["--since", _setting(env, "PHISH_TRIAGE_SINCE", "24h"),
            "--max", str(_number(env, "PHISH_TRIAGE_MAX", 200)),
            "--out", export_path]
    if _flag(env, "PHISH_COLLECT_MAILBOX"):
        # Reads message bodies out of the mailbox. graph_submit already opens
        # it; this is a second, broader read, so it is opt-in.
        argv += ["--mailbox", _mailbox(env),
                 "--folder", _setting(env, "PHISH_FOLDER", "inbox")]
        for address in _deny_checks(env):
            argv += ["--deny-check", address]
    else:
        argv.append("--no-mailbox")
    if _flag(env, "PHISH_NO_HUNTING"):
        argv.append("--no-hunting")
    for domain in _addresses(env, "PHISH_ORG_DOMAINS"):
        argv += ["--org-domain", domain]
    if org_context_path:
        argv += ["--org-context", org_context_path]
    if notes_path:
        argv += ["--reporter-notes", notes_path]
    api_version = _setting(env, "PHISH_API_VERSION")
    if api_version:
        argv += ["--api-version", api_version]
    return argv


def triage_argv(env, export_path, report_path, org_context_path=None):
    """triage.py flags. Markdown to a file, JSON to stdout (captured)."""
    argv = [export_path, "--format", "both", "--out", report_path,
            "--stuck-hours", str(_number(env, "PHISH_STUCK_HOURS", 4)),
            "--large-scope", str(_number(env, "PHISH_LARGE_SCOPE", 100))]
    for domain in _addresses(env, "PHISH_ORG_DOMAINS"):
        argv += ["--org-domain", domain]
    if org_context_path:
        argv += ["--org-context", org_context_path]
    return argv


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

def managed_identity_token(client_id=None):
    """A Graph token for the Function App's managed identity."""
    from azure.identity import ManagedIdentityCredential
    credential = ManagedIdentityCredential(client_id=client_id) if client_id \
        else ManagedIdentityCredential()
    return credential.get_token(GRAPH_SCOPE).token


@contextlib.contextmanager
def graph_credentials(env, token_provider=None):
    """Make the scripts' credentials available in os.environ for one run.

    PHISH_GRAPH_AUTH=managed_identity (default): fetch a token now and put it
    in GRAPH_ACCESS_TOKEN only for the duration of the run. The scripts never
    refresh a supplied token, which is fine: a managed-identity token outlives
    any single invocation.

    PHISH_GRAPH_AUTH=client_secret: GRAPH_TENANT_ID / GRAPH_CLIENT_ID /
    GRAPH_CLIENT_SECRET are already app settings (the secret as a Key Vault
    reference); the scripts use them as-is.
    """
    if _setting(env, "GRAPH_ACCESS_TOKEN"):
        raise ConfigError("GRAPH_ACCESS_TOKEN is set as an app setting. Remove it: a "
                          "static token expires, and it would override the configured "
                          "credentials. The wrapper fetches a fresh one per run.")
    mode = (_setting(env, "PHISH_GRAPH_AUTH", "managed_identity")).lower()

    if mode == "client_secret":
        missing = [name for name in ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET")
                   if not _setting(env, name)]
        if missing:
            raise ConfigError("PHISH_GRAPH_AUTH=client_secret but %s not set"
                              % ", ".join(missing))
        yield
        return

    if mode != "managed_identity":
        raise ConfigError("PHISH_GRAPH_AUTH must be managed_identity or client_secret, got %r"
                          % mode)

    provider = token_provider or managed_identity_token
    token = provider(_setting(env, "PHISH_MANAGED_IDENTITY_CLIENT_ID"))
    os.environ["GRAPH_ACCESS_TOKEN"] = token
    try:
        yield
    finally:
        os.environ.pop("GRAPH_ACCESS_TOKEN", None)


# --------------------------------------------------------------------------
# Blob storage
# --------------------------------------------------------------------------

class BlobStore:
    """The one container this app keeps its state and outputs in.

    PHISH_STORAGE_ACCOUNT_URL -> managed identity (needs Storage Blob Data
    Contributor on the account or container). Otherwise a connection string
    from PHISH_STORAGE_CONNECTION_STRING, falling back to AzureWebJobsStorage.
    """

    def __init__(self, env):
        from azure.core import MatchConditions
        from azure.core.exceptions import (ResourceExistsError, ResourceModifiedError,
                                           ResourceNotFoundError)
        from azure.storage.blob import BlobServiceClient, ContentSettings

        self._match = MatchConditions
        self._exists = ResourceExistsError
        self._modified = ResourceModifiedError
        self._not_found = ResourceNotFoundError
        self._content_settings = ContentSettings

        account_url = _setting(env, "PHISH_STORAGE_ACCOUNT_URL")
        if account_url:
            from azure.identity import ManagedIdentityCredential
            client_id = _setting(env, "PHISH_MANAGED_IDENTITY_CLIENT_ID")
            credential = ManagedIdentityCredential(client_id=client_id) if client_id \
                else ManagedIdentityCredential()
            service = BlobServiceClient(account_url, credential=credential)
        else:
            connection = (_setting(env, "PHISH_STORAGE_CONNECTION_STRING")
                          or _setting(env, "AzureWebJobsStorage"))
            if not connection:
                raise ConfigError("no storage configured: set PHISH_STORAGE_ACCOUNT_URL "
                                  "(managed identity) or PHISH_STORAGE_CONNECTION_STRING")
            service = BlobServiceClient.from_connection_string(connection)

        self.container = service.get_container_client(
            _setting(env, "PHISH_STORAGE_CONTAINER", DEFAULT_CONTAINER))
        try:
            self.container.create_container()
        except ResourceExistsError:
            pass

    def read(self, name):
        """(bytes, etag), or (None, None) if the blob does not exist."""
        try:
            download = self.container.get_blob_client(name).download_blob()
            return download.readall(), download.properties.etag
        except self._not_found:
            return None, None

    def write(self, name, data, etag=None, expect_absent=False,
              content_type="application/json"):
        """Upload. With `etag`, only if unchanged; with `expect_absent`, only if new."""
        blob = self.container.get_blob_client(name)
        kwargs = {"content_settings": self._content_settings(content_type=content_type)}
        try:
            if etag:
                blob.upload_blob(data, overwrite=True, etag=etag,
                                 match_condition=self._match.IfNotModified, **kwargs)
            else:
                blob.upload_blob(data, overwrite=not expect_absent, **kwargs)
        except (self._modified, self._exists) as exc:
            raise StateConflict("%s changed during this run (%s)"
                                % (name, exc.__class__.__name__))


# --------------------------------------------------------------------------
# Running a script
# --------------------------------------------------------------------------

class _LogWriter(io.TextIOBase):
    """Forward a script's stderr to logging, one record per line."""

    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._buffer = ""

    def writable(self):
        return True

    def write(self, text):
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line.strip():
                self._logger.info(line.rstrip())
        return len(text)

    def flush(self):
        if self._buffer.strip():
            self._logger.info(self._buffer.rstrip())
        self._buffer = ""


def call_script(main, argv, logger=log):
    """Run a script's main(argv). Returns (exit_code, captured stdout)."""
    out = io.StringIO()
    err = _LogWriter(logger)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as exc:
                # argparse errors, and graph_submit's "no usable credentials".
                code = exc.code
                if code is not None and not isinstance(code, int):
                    logger.error(str(code))
                    code = 2
    finally:
        err.flush()
    return (code or 0), out.getvalue()


def json_documents(text):
    """Every JSON value in `text`. graph_submit --json can print two in one run."""
    decoder = json.JSONDecoder()
    docs, index = [], 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return docs
        try:
            doc, index = decoder.raw_decode(text, index)
        except ValueError:
            return docs
        docs.append(doc)


def _raise_for_exit(script, code, detail=""):
    if code == 0:
        return
    if code == 3:
        raise ScopeCheckFailed(
            "%s: mailbox scope check failed (exit 3). The app can read a mailbox named "
            "in PHISH_DENY_CHECK, or cannot read PHISH_MAILBOX. Nothing was read or "
            "submitted. Fix the Exchange scope before the next run.%s" % (script, detail), 3)
    if code == 1:
        raise RunFailed("%s: at least one message failed (exit 1); the others were "
                        "processed and recorded.%s" % (script, detail), 1)
    raise RunFailed("%s: run failed (exit %s): auth, permissions or listing. See the "
                    "log lines above.%s" % (script, code, detail), code)


def _stamp(now=None):
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def _read_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def _write_file(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


# --------------------------------------------------------------------------
# Job 1: submit forwarded reports to Defender
# --------------------------------------------------------------------------

def run_submit(env=None, store=None, token_provider=None, now=None, logger=log):
    """graph_submit.py against the shared mailbox, with its state in Blob storage.

    Returns graph_submit's counts, e.g. {"submitted": 3, "skipped": 1}.
    """
    env = os.environ if env is None else env
    with _RUN_LOCK:
        argv_probe = submit_argv(env, state_path=None)   # fail on config before any I/O
        dry_run = "--dry-run" in argv_probe
        store = store or BlobStore(env)
        state_blob = _setting(env, "PHISH_STATE_BLOB", DEFAULT_STATE_BLOB)
        workdir = tempfile.mkdtemp(prefix="phish-submit-")
        try:
            state_path = os.path.join(workdir, "state.json")
            before, etag = store.read(state_blob)
            if before is not None:
                _write_file(state_path, before)

            argv = submit_argv(env, state_path)
            logger.info("graph_submit %s", " ".join(argv))
            failure = None
            code, stdout = None, ""
            try:
                with graph_credentials(env, token_provider):
                    code, stdout = call_script(graph_submit.main, argv, logger)
            except ConfigError:
                raise
            except Exception as exc:          # the script's own finally saved state
                failure = exc

            after = _read_file(state_path)
            if dry_run:
                # graph_submit records dry-run messages as processed. Persisting
                # that would make the real run skip them, so a dry run never
                # writes state back.
                logger.info("dry run: state not written back")
            elif after is not None and after != before:
                store.write(state_blob, after, etag=etag, expect_absent=before is None)

            if failure is not None:
                raise failure

            docs = json_documents(stdout)
            outcome = next((d for d in docs if isinstance(d, dict) and "counts" in d), {})
            counts = outcome.get("counts") or {}
            if outcome.get("results") and _flag(env, "PHISH_KEEP_RUN_RESULTS", True):
                store.write("runs/submit/%s.json" % _stamp(now),
                            json.dumps(outcome, indent=2).encode("utf-8"))
            logger.info("graph_submit counts: %s", json.dumps(counts, sort_keys=True))
            _raise_for_exit("graph_submit", code)
            return counts
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Job 2: collect the queue and triage it
# --------------------------------------------------------------------------

def run_triage(env=None, store=None, token_provider=None, now=None, logger=log):
    """collect_export.py then triage.py; export and report land in Blob storage.

    Returns the blob names written and triage's lane counts.
    """
    env = os.environ if env is None else env
    with _RUN_LOCK:
        collect_argv(env, "export.json")                 # fail on config before any I/O
        store = store or BlobStore(env)
        stamp = _stamp(now)
        workdir = tempfile.mkdtemp(prefix="phish-triage-")
        try:
            export_path = os.path.join(workdir, "export.json")
            report_path = os.path.join(workdir, "report.md")

            org_context_path = None
            org_context_blob = _setting(env, "PHISH_ORG_CONTEXT_BLOB")
            if org_context_blob:
                data, _ = store.read(org_context_blob)
                if data is None:
                    raise ConfigError("PHISH_ORG_CONTEXT_BLOB=%s does not exist in the "
                                      "container" % org_context_blob)
                org_context_path = os.path.join(workdir, "org-context.json")
                _write_file(org_context_path, data)

            notes_path = None
            if _flag(env, "PHISH_CAPTURE_REPORTER_NOTE"):
                # Read-only use of the submit job's state: the notes it captured.
                notes_path = os.path.join(workdir, "submit-state.json")
                data, _ = store.read(_setting(env, "PHISH_STATE_BLOB", DEFAULT_STATE_BLOB))
                if data is not None:
                    _write_file(notes_path, data)
                # Absent file -> collect_export records that in collection_notes.

            argv = collect_argv(env, export_path, org_context_path, notes_path)
            logger.info("collect_export %s", " ".join(argv))
            with graph_credentials(env, token_provider):
                code, _ = call_script(collect_export.main, argv, logger)
            _raise_for_exit("collect_export", code)

            export = _read_file(export_path)
            if export is None:
                raise RunFailed("collect_export exited 0 but wrote no export")
            written = {"export": "exports/%s.json" % stamp}
            store.write(written["export"], export)
            for note in (json.loads(export.decode("utf-8")).get("export_meta") or {}) \
                    .get("collection_notes") or []:
                logger.warning("collection note: %s", note)

            code, stdout = call_script(triage.main,
                                       triage_argv(env, export_path, report_path,
                                                   org_context_path), logger)
            _raise_for_exit("triage", code)
            report = _read_file(report_path) or b""
            docs = json_documents(stdout)
            result = docs[-1] if docs else {}

            written["report"] = "reports/%s.md" % stamp
            written["results"] = "reports/%s.json" % stamp
            results_bytes = json.dumps(result, indent=2, default=str).encode("utf-8")
            store.write(written["report"], report, content_type="text/markdown")
            store.write(written["results"], results_bytes)
            store.write("reports/latest.md", report, content_type="text/markdown")
            store.write("reports/latest.json", results_bytes)

            logger.info("triage counts: %s priorities: %s",
                        json.dumps(result.get("counts") or {}, sort_keys=True),
                        json.dumps(result.get("priorities") or {}, sort_keys=True))
            return {"blobs": written, "counts": result.get("counts") or {},
                    "priorities": result.get("priorities") or {}}
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
