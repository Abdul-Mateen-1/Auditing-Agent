import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

import agent
import tools
from reporting import validate_report, write_report

URL = "https://github.com/example/demo"


def response(steps=None, text=None, status="completed", id="interaction-test"):
    return NS(steps=steps, output_text=text, status=status, id=id)


def call(name, args=None):
    return NS(type="function_call", name=name, arguments=args or {}, id="call-test")


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        (self.root / ".github").mkdir()
        (self.root / ".github" / "ci.yml").write_text("permissions: write-all\n")
        (self.root / "app.py").write_text('print("hello")\npassword = "test-sensitive-value"\n')
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("private metadata")

    def test_inventory_includes_hidden_configuration_excludes_git(self):
        self.assertEqual(tools.list_files(self.root), [".github/ci.yml", "app.py"])

    def test_read_numbered_paginated_redacted_and_unchanged(self):
        path = self.root / "app.py"
        before = path.read_bytes()
        result = tools.read_file(self.root, "app.py", 2, 2)
        self.assertIn("2: password = [REDACTED]", result)
        self.assertNotIn("test-sensitive-value", result)
        self.assertEqual(path.read_bytes(), before)

    def test_path_escape_and_metadata_rejected(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside")
        try:
            (self.root / "escape").symlink_to(outside)
        except OSError:
            # Windows without Developer Mode cannot create symlinks.
            pass
        names = ["../outside.txt", str(outside), ".git/config"]
        if (self.root / "escape").is_symlink():
            names.append("escape")
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                tools.read_file(self.root, name)
        self.assertNotIn("escape", tools.list_files(self.root))

    def test_search_literal_case_insensitive_bounded(self):
        self.assertEqual(tools.search_code(self.root, "PRINT"), ['app.py:1: print("hello")'])
        (self.root / "many.txt").write_text("match\n" * 70)
        self.assertEqual(len(tools.search_code(self.root, "match")), 50)
        with self.assertRaises(ValueError):
            tools.search_code(self.root, "")

    def test_binary_size_and_line_bounds(self):
        (self.root / "binary").write_bytes(b"\x00data")
        (self.root / "large").write_bytes(b"x" * (tools.MAX_FILE_BYTES + 1))
        for name in ["binary", "large"]:
            with self.assertRaises(ValueError):
                tools.read_file(self.root, name)
        with self.assertRaises(ValueError):
            tools.read_file(self.root, "app.py", 0, 2)

    def test_git_history_read_only(self):
        # Replace fake metadata with a real, entirely local fixture repository.
        import shutil

        shutil.rmtree(self.root / ".git")

        def git(*args):
            return subprocess.run(
                ["git", *args], cwd=self.root, capture_output=True, text=True, check=True
            ).stdout

        git("init", "-q")
        git("add", ".")
        git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "Initial fixture",
        )
        before = git("status", "--porcelain")
        self.assertIn("Initial fixture", tools.git_log(self.root))
        self.assertEqual(before, git("status", "--porcelain"))


class AgentTests(unittest.TestCase):
    setUp = ToolTests.setUp

    def make_agent(self, responses, **kwargs):
        client = NS(interactions=NS(create=Mock(side_effect=responses)))
        return agent.Auditor(client, self.root, URL, **kwargs)

    def test_dynamic_followup_and_final_report(self):
        final = json.dumps({"repository": URL, "violations": []})
        auditor = self.make_agent(
            [
                response([call("list_files")]),
                response([call("read_file", {"path": "app.py"})]),
                response(text=final),
            ]
        )
        self.assertEqual(auditor.run()["violations"], [])
        requests = auditor.client.interactions.create.call_args_list
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[1].kwargs["previous_interaction_id"], "interaction-test")
        result = requests[2].kwargs["input"][0]
        self.assertEqual(result["call_id"], "call-test")
        self.assertNotIn("test-sensitive-value", result["result"][0]["text"])

    def test_tool_failure_sent_back_to_model(self):
        auditor = self.make_agent(
            [
                response([call("read_file", {"path": "missing"})]),
                response([call("list_files")]),
                response(text=json.dumps({"repository": URL, "violations": []})),
            ]
        )
        auditor.run()
        request = auditor.client.interactions.create.call_args_list[1].kwargs
        self.assertFalse(json.loads(request["input"][0]["result"][0]["text"])["ok"])

    def test_none_steps_and_failed_status(self):
        for item in [response(), response(status="failed")]:
            with self.assertRaises(RuntimeError):
                self.make_agent([item]).run()

    def test_report_without_tools_rejected(self):
        with self.assertRaises(RuntimeError):
            self.make_agent(
                [response(text=json.dumps({"repository": URL, "violations": []}))]
            ).run()

    def test_budget_and_cache(self):
        auditor = self.make_agent([response([call("list_files")])] * 3, max_rounds=2)
        with self.assertRaises(RuntimeError):
            auditor.run()
        with patch.object(tools, "list_files", return_value=["app.py"]) as listing:
            auditor = self.make_agent([])
            auditor.run_tool("list_files", {})
            auditor.run_tool("list_files", {})
            listing.assert_called_once()

    def test_invalid_json_correction(self):
        auditor = self.make_agent(
            [
                response([call("list_files")]),
                response(text="invalid"),
                response(text=json.dumps({"repository": URL, "violations": []})),
            ]
        )
        self.assertEqual(auditor.run()["violations"], [])

    def test_schema_citations_and_redaction(self):
        violation = dict(
            rule_id="SEC-001",
            category="security",
            severity="high",
            file="app.py",
            line=2,
            description="Hardcoded password",
            evidence="password = test-sensitive-value",
            recommendation="Read from environment",
        )

        def validate(item, observed=None):
            return validate_report(
                json.dumps({"repository": URL, "violations": [item]}),
                URL,
                self.root,
                observed or {"app.py": {2}},
            )

        report = validate(violation)
        self.assertNotIn("test-sensitive-value", json.dumps(report))
        for change in [
            {"line": 99},
            {"file": "missing.py"},
            {"severity": "urgent"},
            {"file": None},
        ]:
            with self.assertRaises(ValueError):
                validate({**violation, **change})
        with self.assertRaises(ValueError):
            validate_report(
                json.dumps({"repository": URL, "violations": [violation, violation]}),
                URL,
                self.root,
                {"app.py": {2}},
            )
        output = self.root / "report.json"
        write_report(output, report)
        self.assertEqual(json.loads(output.read_text()), report)

    def test_request_matches_installed_sdk(self):
        from google.genai._gaos import models, utils

        body = dict(
            model=agent.MODEL,
            input="Audit",
            tools=agent.TOOL_DECLARATIONS,
            system_instruction=agent.SYSTEM_INSTRUCTION,
        )
        utils.unmarshal({"body": body}, models.CreateInteractionRequest)

    def test_cli_invalid_url_and_missing_key(self):
        for url in ["file:///tmp/repo", "https://example.com/x/y", "https://github.com/a/.."]:
            with self.assertRaises(ValueError):
                agent.validate_repo_url(url)
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                agent.main(["--repo", URL, "--output", str(self.root / "report.json")]), 1
            )
            self.assertFalse((self.root / "report.json").exists())


class CliIntegrationTests(unittest.TestCase):
    def test_complete_cli_writes_contract_and_cleans_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            trace = Path(temporary) / "trace.jsonl"
            roots = []

            def clone(url, root):
                root.mkdir()
                (root / "README.md").write_text("Test fixture\n")
                roots.append(root)

            client = Mock()
            client.__enter__ = Mock(return_value=client)
            client.__exit__ = Mock(return_value=False)
            client.interactions.create.side_effect = [
                response([call("list_files")]),
                response(text=json.dumps({"repository": URL, "violations": []})),
            ]
            with (
                patch.dict(os.environ, {"GEMINI_API_KEY": "test-not-a-real-key"}),
                patch.object(agent, "clone_repo", side_effect=clone),
                patch.object(agent.genai, "Client", return_value=client),
            ):
                self.assertEqual(
                    agent.main(["--repo", URL, "--output", str(output), "--trace", str(trace)]), 0
                )
            self.assertEqual(json.loads(output.read_text()), {"repository": URL, "violations": []})
            self.assertFalse(roots[0].exists())
            events = [json.loads(line) for line in trace.read_text().splitlines()]
            self.assertEqual(events[-1]["event"], "completed")
            self.assertNotIn("test-not-a-real-key", trace.read_text())

    def test_failed_cli_does_not_overwrite_report_and_cleans_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            output.write_text("previous report")
            roots = []

            def clone(url, root):
                root.mkdir()
                roots.append(root)

            with (
                patch.dict(os.environ, {"GEMINI_API_KEY": "test-not-a-real-key"}),
                patch.object(agent, "clone_repo", side_effect=clone),
                patch.object(agent.genai, "Client", side_effect=OSError("sensitive raw error")),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(agent.main(["--repo", URL, "--output", str(output)]), 1)
            self.assertEqual(output.read_text(), "previous report")
            self.assertFalse(roots[0].exists())
            self.assertNotIn("sensitive raw error", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
