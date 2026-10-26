# DevOps Repository Auditing Agent

An unattended Python agent that audits public GitHub repositories for evidence-backed
software engineering and DevOps defects. Gemini selects tools and follow-up inspections;
Python implements tool dispatch, budgets, error handling, report validation, and persistence.
No LangChain, LangGraph, n8n, or other agent framework is used.

## Setup

Requires **Python 3.12+**, Git, network access to GitHub/Gemini, and a Gemini API key
with access to the selected model. The CI matrix covers Python 3.12 and 3.13 on Linux and Windows.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Configure credentials without putting them in source files or shell history:

```bash
read -rsp 'Gemini API key: ' GEMINI_API_KEY; echo
export GEMINI_API_KEY
```

On PowerShell, activate with `.venv\Scripts\Activate.ps1` and set credentials using
an appropriate secret/environment configuration. `.env.example` lists supported variable
names. `.env` files are **not loaded automatically**. Never commit real credentials.
`GOOGLE_API_KEY` is also supported by the provider SDK; avoid configuring conflicting keys.

## Run

```bash
python agent.py --repo https://github.com/Abdul-Mateen-1/ml-A1 --output report.json
```

This is noninteractive. Progress goes to stderr. Successful completion atomically writes
JSON and exits 0; fatal errors print a useful message and exit nonzero. Failed runs do not
replace an existing report: check the exit code before treating an old file as a new result.

For metadata-only tool traces or a different model:

```bash
python agent.py --repo https://github.com/owner/project --output report.json \
  --trace audit-trace.jsonl --model gemini-3.5-flash-lite --timeout 30 --max-rounds 25
```

`GEMINI_MODEL` sets the default model. The model must support the Gemini Interactions API
and custom function tools. Model availability, quotas and latency depend on the provider.
The default favors low latency; use a stronger supported model for more demanding audits.
The per-request timeout defaults to 30 seconds, automatic HTTP retries are disabled,
and the investigation is limited to 25 model rounds and 100 tool calls. Multiple calls
are needed for a real audit; total runtime can exceed one request timeout. Increase the
budget deliberately for large repositories. A budget failure never produces a success report.

## Architecture

1. Validate a public HTTPS GitHub URL and credentials.
2. Clone into a fresh, automatically cleaned temporary directory. Never reuse an old clone.
3. Send the model the audit instructions, output schema, and five read-only tool declarations (plus two execution tools when enabled).
4. Interpret model function calls and dispatch only allowlisted tools in Python.
5. Return success/error results to Gemini, preserving call IDs and the interaction chain.
6. Repeat while the model investigates; cache repeated successful calls.
7. Validate the final report, allow two correction attempts, redact likely secrets, and write JSON.

The LLM chooses which files and patterns to investigate. This is not a fixed scanner with
an LLM-written summary. `--trace` records rounds, tool names, success/failure, and totals;
it deliberately excludes raw arguments and file contents. Tests use mocked model decisions,
not invented claims about live API behavior.

| Tool | Behavior |
| --- | --- |
| `list_files()` | Hidden files included; skip `.git`, symlinks, virtual environments, node_modules and caches; maximum 10,000 files |
| `read_file(path, start_line=1, end_line=200)` | Numbered UTF-8 text; inclusive ranges; at most 400 lines and 200 KB per file |
| `search_code(pattern)` | Case-insensitive literal matching; up to 50 numbered matches; skips large, binary, or unreadable files |
| `git_log()` | Latest 10 commit hashes and subject lines, no diffs |
| `git_status()` | Working-tree status without refreshing the index |
| `run_pytest()` | Opt-in Docker sandbox, fixed pytest command, 60-second timeout |
| `run_ruff()` | Opt-in Docker sandbox, default Ruff rules without target configuration |

Tools are in `tools.py`, the explicit control loop and CLI in `agent.py`, and strict report
models/output handling in `reporting.py`. Tests are in `tests/`.

## Optional sandboxed pytest and Ruff checks

The assignment lists execution tools as optional. To enable them, install and start Docker
with Linux container support, then build the trusted image from this repository:

```bash
docker build -f sandbox/Dockerfile -t devops-audit-checks:local .
python agent.py --repo https://github.com/owner/project --output report.json --enable-execution
```

The image contains Python 3.12, pytest, and Ruff. It does not contain project-specific
dependencies. Tests requiring those dependencies, network access, or writes outside `/tmp`
may be unavailable or fail during collection. Such failures do not establish broken project
tests. Ruff uses its default rules and ignores project configuration, so findings must be
checked against the project's actual tooling and conventions.

Each check uses a non-root container, no network, a read-only target mount and root filesystem,
all capabilities dropped, no new privileges, and CPU, memory, process, temporary-storage,
output, and time limits. Host API credentials and the Docker socket are not mounted or
forwarded. Output is redacted and capped at 24 KB. Containers are forcibly removed after
completion or timeout. Missing Docker/image/daemon returns an unavailable check; there is
no host-execution fallback or automatic image pull. A separate hardened Docker host or VM
is appropriate for deliberately hostile targets; containers share the host kernel.

## Report contract

The top-level object has exactly `repository` and `violations`. Each violation contains:
`rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and
`recommendation`. Severity is `critical`, `high`, `medium`, or `low`. File and line are
JSON null where inapplicable. A clean audit has `"violations": []`.

Categories: repository hygiene, dependency management, code quality, testing,
github actions / ci, security, configuration, collaboration, build and release.
The scope excludes ML training, datasets, model validation, and experiment tracking.

Existing-file findings must cite a file actually inspected and, when applicable, a line
returned by a tool. Absence findings use null file/line and must explain the inventory/context.
Duplicate rule/file/line findings are rejected. Citation validation checks provenance, not
whether the model's interpretation is correct; human review remains appropriate.

## Safety and limitations

- Default mode performs repository reads and Git clone/log/status only. Execution tools
  require `--enable-execution` and a separately built Docker sandbox; they never run target
  code directly on the host or install dependencies from the target.
- Traversal, absolute paths, `.git` reads, and symlinks outside the clone are rejected.
- Likely credential patterns and assignments are redacted before model submission/output.
  Pattern-based redaction is defense in depth, not a guarantee for every possible secret.
  Gemini is an external provider: do not use this public-repository tool for private data.
- Repository text is explicitly treated as untrusted data, not agent instructions.
- Alternative dependency, testing, and CI mechanisms must be considered. Missing optional
  files alone are not defects. Remote branch protection cannot be inferred locally.
- Tool size limits, skipped trees, a 10-commit history window, and LLM reasoning can limit
  recall. Unavailable checks must not become fabricated findings. Default mode does not run tests.
- Submodules are not recursively fetched. Clone timeout is 120 seconds. Targets are not modified.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

Tests need no key or external network. They cover tools, traversal/symlink rejection,
redaction, pagination, Git history and unchanged fixtures, dynamic follow-up calls, tool
errors, budgets/cache, missing responses, report correction, schema/citation validation,
SDK request validation, successful/failing CLI persistence/cleanup, execution opt-in,
Docker restrictions, bounded output, timeouts, and unavailable-check handling. GitHub Actions
runs pytest and Ruff on pushes and pull requests with read-only permissions and no API secrets.
The legacy unittest suite also remains runnable with `python -m unittest discover -s tests -v`.

## Generate the required authentic sample report

After configuring a valid API key, run:

```bash
python agent.py --repo https://github.com/Abdul-Mateen-1/ml-A1 \
  --output sample_report.json --trace sample_trace.jsonl
python -m json.tool sample_report.json
```

Review the genuine findings and commit the resulting `sample_report.json` with your
submission. No API key was available during development, so a live audit and authentic sample
remain unverified. Do not submit until this live run succeeds. Hidden-repository accuracy also
requires empirical evaluation; passing offline tests does not establish precision or recall.

See [REVIEW.md](REVIEW.md) for requirement coverage, review changes, and verification limits.
