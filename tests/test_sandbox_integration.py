"""Real container checks, enabled in the dedicated Linux CI job."""

import hashlib
import os

import pytest

import tools


@pytest.mark.skipif(
    os.getenv("AUDIT_SANDBOX_TESTS") != "1", reason="Requires prebuilt Docker image"
)
def test_real_sandbox_checks_leave_target_unchanged(tmp_path):
    (tmp_path / "test_example.py").write_text("def test_example():\n    assert True\n")
    (tmp_path / "app.py").write_text("import os\n")
    # pytest uses a non-root UID and must be able to traverse the fixture directories.
    for path in (tmp_path.parent.parent, tmp_path.parent, tmp_path):
        path.chmod(0o755)

    def snapshot():
        return {
            p.relative_to(tmp_path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in tmp_path.rglob("*")
            if p.is_file()
        }

    before = snapshot()
    tests = tools.run_pytest(tmp_path)
    assert tests["available"], tests
    assert tests["exit_code"] == 0, tests
    lint = tools.run_ruff(tmp_path)
    assert lint["available"], lint
    assert lint["exit_code"] == 1, lint
    assert "F401" in lint["output"]
    assert snapshot() == before
