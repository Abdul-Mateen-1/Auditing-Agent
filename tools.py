"""Bounded repository inspection, with optional isolated execution checks."""

import re
import subprocess
import threading
import uuid
from pathlib import Path

MAX_FILE_BYTES = 200_000
MAX_FILES = 10_000
MAX_MATCHES = 50
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
_SECRET_ASSIGNMENT = re.compile(
    r'(?i)((?:[\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w-]*)[\s"\']*[:=]\s*)([^\r\n]+)'
)
_SECRET_VALUES = re.compile(
    r"AIza[\w-]{30,}|AKIA[0-9A-Z]{16}|gh[pousr]_[\w]{20,}|github_pat_[\w]+|AQ\.[\w-]{30,}|sk-[\w-]{20,}"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)", re.S
)


def redact(text: str) -> str:
    """Keep secret indicators while removing likely credential values."""
    text = _PRIVATE_KEY.sub(
        lambda match: "[REDACTED PRIVATE KEY]" + "\n" * match.group().count("\n"), text
    )
    text = _SECRET_VALUES.sub("[REDACTED]", text)
    return _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)


def safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("Expected a nonempty repository-relative path")
    root = root.resolve()
    candidate = root / relative
    if any(
        part.is_symlink()
        for part in (candidate, *candidate.parents)
        if part != root and root in part.parents
    ):
        raise ValueError("Symlink paths cannot be inspected")
    target = (root / relative).resolve()
    if not target.is_relative_to(root) or target == root:
        raise ValueError("Path escapes the repository or names its root")
    if ".git" in target.relative_to(root).parts:
        raise ValueError("Git metadata cannot be read directly; use git_log")
    return target


def list_files(repo_folder: Path) -> list[str]:
    """List files including hidden configuration; skip symlinks and large generated trees."""
    root = repo_folder.resolve()
    files = []
    for directory, dirs, names in root.walk(follow_symlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (directory / d).is_symlink())
        for name in sorted(names):
            path = directory / name
            if path.is_file() and not path.is_symlink():
                files.append(path.relative_to(root).as_posix())
                if len(files) > MAX_FILES:
                    raise ValueError(f"Repository exceeds the {MAX_FILES}-file inspection limit")
    return sorted(files)


def _text(root: Path, relative: str) -> str:
    path = safe_path(root, relative)
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds {MAX_FILE_BYTES}-byte inspection limit")
    if b"\x00" in data:
        raise ValueError("Binary files cannot be read as text")
    return redact(data.decode("utf-8"))


def read_file(repo_folder: Path, file_path: str, start_line: int = 1, end_line: int = 200) -> str:
    if (
        type(start_line) is not int
        or type(end_line) is not int
        or start_line < 1
        or end_line < start_line
    ):
        raise ValueError("Expected 1-based inclusive line range")
    if end_line - start_line >= 400:
        raise ValueError("Read at most 400 lines per call")
    lines = _text(repo_folder, file_path).splitlines()
    result = "\n".join(
        f"{n}: {line}" for n, line in enumerate(lines[start_line - 1 : end_line], start_line)
    )
    return (
        result
        + f"\n[total lines: {len(lines)}; returned range: {start_line}-{min(end_line, len(lines))}]"
    )


def search_code(repo_folder: Path, pattern: str) -> list[str]:
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 200:
        raise ValueError("Search text must contain 1-200 characters")
    matches = []
    for relative in list_files(repo_folder):
        try:
            lines = _text(repo_folder, relative).splitlines()
        except (OSError, ValueError):
            continue
        for n, line in enumerate(lines, 1):
            if pattern.casefold() in line.casefold():
                matches.append(f"{relative}:{n}: {line.strip()[:1000]}")
                if len(matches) >= MAX_MATCHES:
                    return matches
    return matches


def git_log(repo_folder: Path) -> str:
    result = subprocess.run(
        ["git", "--no-pager", "log", "-10", "--format=%h %s"],
        cwd=repo_folder,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return redact(result.stdout[:12_000])


def git_status(repo_folder: Path) -> str:
    """Read tracked/untracked state without refreshing the Git index."""
    result = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=repo_folder,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return redact(result.stdout[:12_000])


def _capture_bounded(command: list[str], timeout: int) -> tuple[int, bytes]:
    """Drain child output continuously while retaining at most 24,001 bytes."""
    data = bytearray()
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:

        def drain():
            while chunk := process.stdout.read(8192):
                if len(data) < 24_001:
                    data.extend(chunk[: 24_001 - len(data)])

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            reader.join(timeout=5)
    return code, bytes(data)


def _sandbox_check(repo_folder: Path, check: str) -> dict:
    """Execute fixed checks in a prebuilt, restricted Docker container only."""
    commands = {
        "pytest": [
            "python",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp=/tmp/pytest",
        ],
        "ruff": ["ruff", "check", "--isolated", "--no-cache", "--output-format=json", "."],
    }
    name = "devops-audit-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--pids-limit=64",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--log-driver=none",
        "--ulimit",
        "fsize=1048576:1048576",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
        "--mount",
        f"type=bind,source={repo_folder.resolve()},target=/repo,readonly",
        "--workdir=/repo",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "--env=HOME=/tmp",
        "devops-audit-checks:local",
        *commands[check],
    ]
    try:
        code, data = _capture_bounded(command, timeout=60)
        return {
            "check": check,
            "exit_code": code,
            "available": code not in {125, 126, 127},
            "output": redact(data[:24_000].decode("utf-8", errors="replace")),
            "truncated": len(data) > 24_000,
        }
    except FileNotFoundError:
        return {"check": check, "available": False, "error": "Docker is not installed"}
    except subprocess.TimeoutExpired:
        return {"check": check, "available": False, "error": "Sandbox check exceeded 60 seconds"}
    finally:
        # A client timeout alone does not stop the container. Always remove it.
        try:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass


def run_pytest(repo_folder: Path) -> dict:
    """Run pytest with network disabled and the target mounted read-only."""
    return _sandbox_check(repo_folder, "pytest")


def run_ruff(repo_folder: Path) -> dict:
    """Run Ruff's default rules, ignoring target configuration, in Docker."""
    return _sandbox_check(repo_folder, "ruff")
