import argparse
import contextlib
import io
import json
import os
import sys
from collections import Counter
from pathlib import Path

from comment_extractor import extract_from_file
from commit_extractor import extract_commit_messages
from scanner import VulnerabilityScanner
from severity_classifier import SEVERITY_ORDER, classify

DEFAULT_EXCLUDES = {
    "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", "build", "dist", "htmlcov",
}

# Design choice: how serious each scanner finding type is on the 4-level scale
SCANNER_SEVERITY = {
    "SQL Injection": "critical",
    "Command Injection": "critical",
    "Hardcoded Secret": "high",
    "Path Traversal": "high",
}

SCANNER_RECOMMENDATIONS = {
    "SQL Injection": "Use a parameterized query: pass the values as a separate argument to execute() instead of building the SQL string.",
    "Command Injection": "Pass the command as a list of arguments, avoid shell=True, and validate any user input before it reaches the command.",
    "Hardcoded Secret": "Move this secret into an environment variable or secrets manager, and rotate it because it may already be exposed.",
    "Path Traversal": "Resolve the path and check that it stays inside the allowed folder before opening it.",
}

LINK_WINDOW = 3  # a comment and a scanner finding this close are linked
MAX_FILE_BYTES = 500_000


def make_issue(source, severity, category, text, recommendation,
               file=None, line=None, context=""):
    return {
        "source": source,
        "severity": severity,
        "category": category,
        "file": file,
        "line": line,
        "text": text,
        "context": context,
        "recommendation": recommendation,
        "also_flagged_by": [],
    }


def python_files(root, excludes):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in excludes and not d.startswith(".")
        )
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def scan_files(root, excludes):
    """Return (issues, files_scanned, files_with_problems)."""
    scanner = VulnerabilityScanner()
    issues = []
    files = skipped = 0
    for path in python_files(Path(root), excludes):
        files += 1
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            for record in extract_from_file(str(path)):
                result = classify(record)
                if result:
                    issues.append(make_issue(
                        "comment", result["severity"], result["category"],
                        result["text"], result["recommendation"],
                        file=str(path), line=result["location"],
                        context=result["raw_context"],
                    ))
            for finding in scanner.scan(str(path)):
                kind = finding["type"]
                issues.append(make_issue(
                    "scanner", SCANNER_SEVERITY.get(kind, "high"), kind,
                    finding["snippet"],
                    SCANNER_RECOMMENDATIONS.get(kind, "Review this code."),
                    file=str(path), line=finding["line"],
                ))
        if buffer.getvalue().strip():
            skipped += 1  # the file could not be fully read or parsed
    return issues, files, skipped


def scan_commits(repo, max_commits):
    """Return (issues, commits_read)."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        records = extract_commit_messages(str(repo), max_commits)
    issues = []
    for record in records:
        result = classify(record)
        if result:
            issues.append(make_issue(
                "commit", result["severity"], result["category"],
                result["text"], result["recommendation"],
                context=f"commit {result['location']} ({result['raw_context']})",
            ))
    return issues, len(records)


def link_findings(issues):
    """Cross-reference comment issues and scanner findings in the same file."""
    scanner_by_file = {}
    for issue in issues:
        if issue["source"] == "scanner":
            scanner_by_file.setdefault(issue["file"], []).append(issue)
    for issue in issues:
        if issue["source"] != "comment":
            continue
        for other in scanner_by_file.get(issue["file"], []):
            if abs(other["line"] - issue["line"]) <= LINK_WINDOW:
                issue["also_flagged_by"].append(
                    f"scanner: {other['category']} at line {other['line']}")
                other["also_flagged_by"].append(
                    f"comment at line {issue['line']}")


def filter_and_sort(issues, min_severity):
    floor = SEVERITY_ORDER[min_severity]
    kept = [i for i in issues if SEVERITY_ORDER[i["severity"]] >= floor]
    return sorted(kept, key=lambda i: (
        -SEVERITY_ORDER[i["severity"]],
        0 if i["also_flagged_by"] else 1,
        i["file"] or "",
        i["line"] or 0,
    ))


def where(issue):
    if issue["file"]:
        return f"{issue['file']}:{issue['line']}"
    return issue["context"]


def print_text_report(root, issues, files, skipped, commits, limit):
    counts = Counter(i["severity"] for i in issues)
    print(f"TRIAGE REPORT for {root}")
    print(f"Scanned {files} Python files ({skipped} had problems and were partly skipped) "
          f"and {commits} commit messages.")
    print("Issues found: " + ", ".join(
        f"{counts.get(level, 0)} {level}" for level in ("critical", "high", "medium", "low")))
    print()
    if not issues:
        print("No issues found at or above the chosen severity.")
        return
    shown = issues if limit <= 0 else issues[:limit]
    labels = {"comment": "Comment", "scanner": "Code", "commit": "Message"}
    for issue in shown:
        print(f"[{issue['severity'].upper()}] {issue['category']} ({issue['source']}) - {where(issue)}")
        first_line = issue["text"].splitlines()[0] if issue["text"] else ""
        print(f"  {labels[issue['source']]}: {first_line[:200]}")
        print(f"  Suggestion: {issue['recommendation']}")
        for note in issue["also_flagged_by"]:
            print(f"  Also flagged: {note}")
        print()
    if len(shown) < len(issues):
        print(f"... {len(issues) - len(shown)} more. Use --limit 0 or --format json to see all.")
    if commits:
        print("Note: commit-message findings usually describe work that is already done, so treat them as hints.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan a codebase and triage developer comments, commit messages "
                    "and code vulnerabilities by severity."
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="Folder (or single .py file) to scan (default: current folder)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                        help="Hide issues below this level (default: low)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max issues to print in text mode, 0 = all (default: 50)")
    parser.add_argument("--no-commits", action="store_true", help="Skip git commit messages")
    parser.add_argument("--max-commits", type=int, default=200)
    parser.add_argument("--exclude", action="append", default=[],
                        help="Extra folder name to skip (repeatable)")
    return parser.parse_args()


def main():
    args = parse_args()
    root = Path(args.path)
    if not root.exists():
        print(f"Path not found: {root}")
        sys.exit(1)

    excludes = DEFAULT_EXCLUDES | set(args.exclude)
    issues, files, skipped = scan_files(root, excludes)

    commits = 0
    if not args.no_commits:
        repo = root if root.is_dir() else root.parent
        commit_issues, commits = scan_commits(repo, args.max_commits)
        issues.extend(commit_issues)

    link_findings(issues)
    issues = filter_and_sort(issues, args.min_severity)

    if args.format == "json":
        summary = {
            "path": str(root),
            "files_scanned": files,
            "files_with_problems": skipped,
            "commits_read": commits,
            "counts": dict(Counter(i["severity"] for i in issues)),
        }
        print(json.dumps({"summary": summary, "issues": issues}, indent=2))
    else:
        print_text_report(root, issues, files, skipped, commits, args.limit)


if __name__ == "__main__":
    main()
