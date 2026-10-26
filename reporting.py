"""Strict report validation and atomic JSON output."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

import tools


class Violation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    rule_id: str = Field(min_length=1)
    category: Literal[
        "repository hygiene",
        "dependency management",
        "code quality",
        "testing",
        "github actions / ci",
        "security",
        "configuration",
        "collaboration",
        "build and release",
    ]
    severity: Literal["critical", "high", "medium", "low"]
    file: str | None
    line: int | None = Field(ge=1)
    description: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    repository: str
    violations: list[Violation]


def validate_report(text, repository, root, observed):
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        text = "\n".join(text.splitlines()[1:-1])
    report = Report.model_validate_json(text)
    if report.repository != repository:
        raise ValueError("Report repository does not match requested URL")
    seen = set()
    for item in report.violations:
        if item.file is None:
            if item.line is not None:
                raise ValueError("A line number requires a file")
        else:
            path = tools.safe_path(root, item.file)
            if not path.is_file() or item.file not in observed:
                raise ValueError("Finding cites a file not inspected through a tool")
            if item.line is not None:
                if item.line not in observed[item.file]:
                    raise ValueError("Finding cites a line not inspected through a tool")
        key = (item.rule_id, item.file, item.line)
        if key in seen:
            raise ValueError("Duplicate finding; consolidate repeated evidence")
        seen.add(key)
    # Defense in depth: redact free text before it reaches disk.
    data = report.model_dump()
    for item in data["violations"]:
        for key in ("description", "evidence", "recommendation"):
            item[key] = tools.redact(item[key])
    return data


def write_report(path: Path, report: dict):
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    filename = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            filename = stream.name
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(filename, path)
    finally:
        if filename:
            Path(filename).unlink(missing_ok=True)
