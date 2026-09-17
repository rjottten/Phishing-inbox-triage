"""The skill bundle ships on its own, so its own files must hold together.

Everything here runs against the folder as it would be unzipped into a skills
directory: the scripts must start with nothing installed, and every path SKILL.md
and the evals name must actually exist. A skill whose frontmatter is malformed or
whose reference is missing fails silently at load time, which is not the kind of
thing a reader notices in review.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "phishing-inbox-triage")
SCRIPTS = os.path.join(SKILL, "scripts")

#: Every script the bundle ships. Named explicitly so a new one has to be added
#: here, rather than quietly shipping unchecked.
SHIPPED_SCRIPTS = (
    "collect_export.py",
    "graph_submit.py",
    "import_defender_csv.py",
    "parse_headers.py",
    "triage.py",
)

#: The ones documented as safe to point at real data because they cannot reach the
#: network. An unenforced claim like that rots.
OFFLINE_SCRIPTS = ("triage.py", "parse_headers.py", "import_defender_csv.py")

NETWORK_MODULES = {"urllib", "http", "socket", "requests", "httpx", "ftplib",
                   "smtplib", "telnetlib", "xmlrpc", "webbrowser", "asyncio"}

#: Siblings the scripts import from each other. Python 3.10+ has
#: sys.stdlib_module_names; these are the non-stdlib names that are still fine.
SHIPPED_MODULES = {n[:-3] for n in SHIPPED_SCRIPTS}


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


class TestScriptsRunStandalone(unittest.TestCase):
    """No package, no install, no site-packages beyond the stdlib."""

    def test_every_shipped_script_starts(self):
        for name in SHIPPED_SCRIPTS:
            path = os.path.join(SCRIPTS, name)
            self.assertTrue(os.path.exists(path), f"{name} is missing")
            proc = subprocess.run([sys.executable, path, "--help"],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{name} --help: {proc.stderr}")

    def test_the_bundle_ships_no_script_that_needs_an_install(self):
        """A new script appearing here is how the no-install guarantee would break.

        The model-assisted tools in agents/ need the Anthropic SDK and network, which
        is exactly why they live outside the bundle. Moving one in would make the
        folder stop working the moment it is unzipped somewhere without pip.
        """
        present = sorted(f for f in os.listdir(SCRIPTS) if f.endswith(".py"))
        self.assertEqual(present, sorted(SHIPPED_SCRIPTS),
                         "an unexpected script is in the bundle; if it needs an "
                         "install it belongs in agents/, and if it does not, add it "
                         "to SHIPPED_SCRIPTS")

    def test_no_shipped_script_imports_a_third_party_package(self):
        """stdlib only. `import anthropic` here would pass its own tests and then
        fail on the analyst's machine."""
        import ast
        stdlib = set(getattr(sys, "stdlib_module_names", ())) | set(SHIPPED_MODULES)
        for name in SHIPPED_SCRIPTS:
            path = os.path.join(SCRIPTS, name)
            tree = ast.parse(read(path), path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    roots = [node.module.split(".")[0]]
                else:
                    continue
                for root in roots:
                    self.assertIn(root, stdlib, f"{name} imports {root!r}, which is not stdlib")

    def test_the_parser_runs_from_an_unzipped_folder(self):
        """cwd is somewhere else entirely — the script must not need the repo."""
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "raw.txt")
            with open(raw, "w", encoding="utf-8") as fh:
                fh.write("From: a@b.example\nSubject: Urgent wire\n")
            proc = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "parse_headers.py"), raw],
                capture_output=True, text=True, cwd=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["flags"],
                             ["urgency_or_finance_subject"])

    def test_triage_runs_from_an_unzipped_folder(self):
        """It imports parse_headers as a sibling, which only works if it resolves
        that path from its own location rather than from the working directory."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "triage.py"),
                 os.path.join(ROOT, "test-data", "mailbox_export.json"),
                 "--format", "json"],
                capture_output=True, text=True, cwd=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(json.loads(proc.stdout)["results"]), 10)


class TestOfflineScriptsStayOffline(unittest.TestCase):

    def test_no_network_capable_import(self):
        import ast
        for name in OFFLINE_SCRIPTS:
            path = os.path.join(SCRIPTS, name)
            tree = ast.parse(read(path), path)
            found = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    found.add(node.module.split(".")[0])
            self.assertEqual(found & NETWORK_MODULES, set(),
                             f"{name} gained a network-capable import")


class TestSkillMetadata(unittest.TestCase):

    def test_frontmatter_is_well_formed(self):
        text = read(SKILL, "SKILL.md")
        self.assertTrue(text.startswith("---\n"), "SKILL.md needs YAML frontmatter")
        front = text.split("---", 2)[1]
        self.assertIn("name: phishing-inbox-triage", front)
        self.assertIn("description:", front)

    def test_the_references_it_promises_exist(self):
        for name in ("exception-criteria.md", "response-actions.md",
                     "report-template.md", "graph-automation.md"):
            self.assertTrue(os.path.exists(os.path.join(SKILL, "references", name)), name)

    def test_every_path_skill_md_names_exists(self):
        text = read(SKILL, "SKILL.md")
        referenced = set(re.findall(r"(?:references|scripts)/[\w.-]+\.(?:md|py)", text))
        self.assertTrue(referenced, "found no reference paths — has the regex gone stale?")
        missing = sorted(p for p in referenced if not os.path.exists(os.path.join(SKILL, p)))
        self.assertEqual(missing, [], "SKILL.md points at files that do not exist")

    def test_the_json_files_parse(self):
        for path in (os.path.join(SKILL, "evals", "evals.json"),
                     os.path.join(ROOT, "test-data", "mailbox_export.json"),
                     os.path.join(ROOT, "test-data", "org-context.example.json")):
            json.loads(read(path))

    def test_eval_file_points_at_files_that_exist(self):
        evals = json.loads(read(SKILL, "evals", "evals.json"))
        for case in evals["evals"]:
            for rel in case.get("files", []):
                self.assertTrue(os.path.exists(os.path.join(ROOT, rel)),
                                f"eval {case['id']} references missing {rel}")


if __name__ == "__main__":
    unittest.main()
