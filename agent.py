from google import genai
from google.genai import types
import argparse
import json
import subprocess
from pathlib import Path
import os
import shutil
import tools
repo_folder = Path("temp-repo")

TOOL_DECLARATIONS = [
    {
        "type": "function",
        "name": "list_files",
        "description": "List repository files recursively, excluding .git metadata. Returns paths relative to the repository root.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "type": "function",
        "name": "read_file",
        "description": "Read a repository file and return its text with 1-based line numbers.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path relative to the repository root."}},
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "search_code",
        "description": "Find up to 50 case-insensitive literal substring matches. Returns file paths, line numbers, and matching text. Skips .git metadata and unreadable or invalid UTF-8 files.",
        "parameters": {
            "type": "object",
            "properties": {"pattern": {"type": "string", "description": "Literal text to search for, not a regular expression."}},
            "required": ["pattern"],
        },
    },
    {
        "type": "function",
        "name": "git_log",
        "description": "Return the 10 most recent commit hashes and one-line messages, without diffs.",
        "parameters": {"type": "object", "properties": {}},
    },
]

def list_files() -> list[str]:
    """List repository files recursively, excluding .git metadata.

    Returns paths relative to the repository root. Use this to discover
    the project structure before inspecting individual files.
    """
    return tools.list_files(repo_folder)


def read_file(path: str) -> str:
    """Read a repository file and return its text with 1-based line numbers.

    Args:
        path: File path relative to the repository root.
    """
    return tools.read_file(repo_folder, path)


def search_code(pattern: str) -> list[str]:
    """Find up to 50 case-insensitive literal substring matches in repository files.

    Returns matches with relative file paths, line numbers, and matching text.
    Excludes .git metadata and skips unreadable or invalid UTF-8 files.

    Args:
        pattern: Literal text to search for, not a regular expression.
    """
    return tools.search_code(repo_folder, pattern)


def git_log() -> str:
    """Return the 10 most recent commit hashes and one-line commit messages.

    Use this to inspect recent development activity. Does not include diffs.
    """
    return tools.git_log(repo_folder)


def empty_dir(path):
    folder = Path(path)
    
    for files in folder.iterdir():
        if files.is_symlink() or files.is_file():
            files.unlink()
        elif files.is_dir():
            shutil.rmtree(files)

def is_dir_empty(dest):
    if not dest.is_dir():
            raise FileNotFoundError("That is not a valid directory")
    
    return not any(dest.iterdir())
    
def clone_repo(repo_url, repo_folder):
    repo_folder.mkdir(parents=True, exist_ok=True)
    
    if is_dir_empty(repo_folder):
        subprocess.run(
                ["git", "clone", "--", repo_url, str(repo_folder)],
                check=True,
                timeout=120,
            )

        
def run_tool(name, arguments, repo_folder):
    if name == "list_files":
        return tools.list_files(repo_folder)

    if name == "read_file":
        return tools.read_file(repo_folder, arguments["path"])

    if name == "search_code":
        return tools.search_code(repo_folder, arguments["pattern"])

    if name == "git_log":
        return tools.git_log(repo_folder)

    raise ValueError(f"Unknown tool: {name}")
    
  
def main():
      
    interaction = client.interactions.create(
        model="gemini-3.5-flash-lite",
        input="Audit this repository for evidence-backed DevOps violations. Use tools to investigate.",
        system_instruction=(
            "Inspect before making claims. Consider acceptable alternatives. "
            "Never repeat secret values."
        ),
        tools=TOOL_DECLARATIONS,
    )
    
    for _ in range(20):
        calls = [
            step for step in interaction.steps
            if step.type == "function_call"
        ]

        if not calls:
            print("Gemini has finished the audit.")
            print(interaction.output_text)
            break

        results = []

        for call in calls:
            print(f"Gemini called: {call.name}")
            tool_output = run_tool(call.name, call.arguments, repo_folder)

            results.append({
                "type": "function_result",
                "name": call.name,
                "call_id": call.id,
                "result": [{
                    "type": "text",
                    "text": json.dumps(tool_output),
                }],
            })

        # This is the next conversation round.
        # The new response replaces the old `interaction`.
        interaction = client.interactions.create(
            model="gemini-3.5-flash-lite",
            previous_interaction_id=interaction.id,
            input=results,
            tools=TOOL_DECLARATIONS,
        )
        
                
        
    
    
if __name__ ==  "__main__":
    
    client = genai.Client()

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    
    clone_repo(args.repo, repo_folder)
    main()
    empty_dir("temp-repo")

