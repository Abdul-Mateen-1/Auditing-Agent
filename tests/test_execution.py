"""Execution tools must remain gated, bounded, and isolated from the host."""

import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import agent
import tools


@pytest.mark.parametrize("name", ["run_pytest", "run_ruff"])
def test_execution_requires_opt_in(tmp_path, name):
    auditor = agent.Auditor(None, tmp_path, "https://github.com/example/demo")
    assert name not in {item["name"] for item in auditor.declarations}
    with patch.object(tools, name) as execute, pytest.raises(ValueError):
        auditor.run_tool(name, {})
    execute.assert_not_called()


@pytest.mark.parametrize("name", ["run_pytest", "run_ruff"])
def test_opt_in_dispatch_and_cache(tmp_path, name):
    auditor = agent.Auditor(
        None, tmp_path, "https://github.com/example/demo", enable_execution=True
    )
    with patch.object(tools, name, return_value={"available": False}) as execute:
        assert auditor.run_tool(name, {}) == {"available": False}
        auditor.run_tool(name, {})
    execute.assert_called_once_with(tmp_path)


@pytest.mark.parametrize("check", ["pytest", "ruff"])
def test_sandbox_command_redaction_truncation_and_cleanup(tmp_path, check):
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        return 1, b"password = sensitive-fixture\n" + b"x" * 24_001

    with (
        patch.object(tools, "_capture_bounded", side_effect=capture),
        patch.object(tools.subprocess, "run") as cleanup,
    ):
        result = getattr(tools, "run_" + check)(tmp_path)
    command = commands[0]
    for flag in [
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--pull=never",
    ]:
        assert flag in command
    assert f"type=bind,source={tmp_path.resolve()},target=/repo,readonly" in command
    assert "devops-audit-checks:local" in command
    assert cleanup.call_args.args[0][:3] == ["docker", "rm", "--force"]
    assert result["available"] is True
    assert result["exit_code"] == 1
    assert result["truncated"] is True
    assert "sensitive-fixture" not in result["output"]


@pytest.mark.parametrize("failure", [FileNotFoundError(), subprocess.TimeoutExpired("docker", 60)])
def test_unavailable_check_is_not_a_pass_and_cleanup_attempted(tmp_path, failure):
    with (
        patch.object(tools, "_capture_bounded", side_effect=failure),
        patch.object(tools.subprocess, "run") as run,
    ):
        result = tools.run_pytest(tmp_path)
    assert result["available"] is False
    assert "exit_code" not in result
    assert run.call_args_list[-1].args[0][:3] == ["docker", "rm", "--force"]


@pytest.mark.parametrize("code", [125, 126, 127])
def test_docker_setup_failure_is_unavailable(tmp_path, code):
    with (
        patch.object(tools, "_capture_bounded", return_value=(code, b"")),
        patch.object(tools.subprocess, "run"),
    ):
        assert tools.run_pytest(tmp_path)["available"] is False


def test_capture_discards_flood_output():
    code, data = tools._capture_bounded([sys.executable, "-c", "print('x' * 1000000)"], 10)
    assert code == 0
    assert len(data) == 24_001


def test_capture_enforces_timeout():
    with pytest.raises(subprocess.TimeoutExpired):
        tools._capture_bounded([sys.executable, "-c", "import time; time.sleep(10)"], 0.1)


def test_execution_results_returned_to_model(tmp_path):
    client = Mock()
    client.interactions.create.side_effect = [
        SimpleNamespace(
            status="completed",
            id="one",
            steps=[
                SimpleNamespace(type="function_call", name="run_pytest", arguments={}, id="check"),
                SimpleNamespace(
                    type="function_call", name="list_files", arguments={}, id="inventory"
                ),
            ],
        ),
        SimpleNamespace(
            status="completed",
            id="two",
            steps=[],
            output_text=json.dumps(
                {"repository": "https://github.com/example/demo", "violations": []}
            ),
        ),
    ]
    with patch.object(tools, "run_pytest", return_value={"available": False, "error": "No Docker"}):
        agent.Auditor(
            client, tmp_path, "https://github.com/example/demo", enable_execution=True
        ).run()
    payload = client.interactions.create.call_args.kwargs["input"][0]
    assert payload["call_id"] == "check"
    assert json.loads(payload["result"][0]["text"])["output"]["available"] is False


def test_unavailable_execution_alone_cannot_complete_audit(tmp_path):
    client = Mock()
    client.interactions.create.side_effect = [
        SimpleNamespace(
            status="completed",
            id="one",
            steps=[
                SimpleNamespace(type="function_call", name="run_pytest", arguments={}, id="check")
            ],
        ),
        SimpleNamespace(
            status="completed",
            id="two",
            steps=[],
            output_text=json.dumps(
                {"repository": "https://github.com/example/demo", "violations": []}
            ),
        ),
    ]
    with (
        patch.object(tools, "run_pytest", return_value={"available": False}),
        pytest.raises(RuntimeError),
    ):
        agent.Auditor(
            client, tmp_path, "https://github.com/example/demo", enable_execution=True
        ).run()


def test_git_status_is_read_only_and_redacted(tmp_path):
    with patch.object(
        tools.subprocess, "run", return_value=SimpleNamespace(stdout="?? new.py\n", returncode=0)
    ) as run:
        assert tools.git_status(tmp_path) == "?? new.py\n"
    assert run.call_args.args[0][:3] == ["git", "--no-optional-locks", "status"]


def test_internal_symlink_cannot_bypass_inventory(tmp_path):
    (tmp_path / "file.txt").write_text("fixture")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "file.txt")
    except OSError:
        pytest.skip("Creating symlinks requires Windows Developer Mode or privileges")
    with pytest.raises(ValueError):
        tools.read_file(tmp_path, "link.txt")
