from pathlib import Path
import subprocess

repo = Path("temp-repo")

def list_files(repo_folder: Path)->list[str]:
    
    files = []
    for item in repo_folder.rglob("*"):
        if item.is_file() and ".git" not in item.parts:
            files.append(item.relative_to(repo_folder).as_posix())
        
    return files

def read_file(repo_folder: Path, file_path: str)->str:
    path = repo_folder / file_path
    lines =  path.read_text(encoding="utf-8", errors="replace").splitlines()
    numbered_lines = []
    for line_number, line in enumerate(lines, start=1):
        numbered_lines.append(f"{line_number}: {line}")
    
    return "\n".join(numbered_lines)

def search_code(repo_folder: Path, pattern: str)->list[str]:
    matches = []

    for relative_path in list_files(repo_folder):
        path = repo_folder / relative_path

        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeError, OSError):
            continue  # Skip binary or unreadable files

        for line_number, line in enumerate(lines, start=1):
            if pattern.lower() in line.lower():
                matches.append(
                    f"{relative_path}:{line_number}: {line.strip()}"
                )

                if len(matches) >= 50:
                    return matches

    return matches
    
def git_log(repo_folder: Path) -> str:
    result = subprocess.run(
        ["git", "log", "-10", "--oneline"],
        cwd=repo_folder,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout
    
    
    
    
