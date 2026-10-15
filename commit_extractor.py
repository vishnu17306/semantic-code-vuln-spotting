import argparse
import subprocess

from severity_classifier import classify_all

FIELD_SEP = "\x1f"
RECORD_SEP = "\x1e"


def extract_commit_messages(repo_path=".", max_count=200):
    """Return recent commit messages as unified records.

    Same shape as the inline comment records:
    text, source_type, location, raw_context.
    """
    cmd = [
        "git", "-C", repo_path, "log", f"--max-count={max_count}",
        f"--pretty=format:%h{FIELD_SEP}%an{FIELD_SEP}%ad{FIELD_SEP}%B{RECORD_SEP}",
        "--date=short",
    ]
    try:
        output = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Could not read git history from {repo_path}: {e}")
        return []

    records = []
    for chunk in output.split(RECORD_SEP):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(FIELD_SEP, 3)
        if len(parts) < 4:
            continue
        commit_hash, author, date, message = parts
        message = message.strip()
        if not message:
            continue
        records.append({
            "text": message,
            "source_type": "commit_message",
            "location": commit_hash,
            "raw_context": f"{author}, {date}",
        })
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Triage commit messages by severity.")
    parser.add_argument("--repo", default=".", help="Path to the git repo (default: current folder)")
    parser.add_argument("--max", type=int, default=200, help="How many recent commits to read")
    args = parser.parse_args()

    records = extract_commit_messages(args.repo, args.max)
    print(f"Read {len(records)} commit messages.\n")

    issues = classify_all(records)
    if not issues:
        print("No issues found in commit messages.")
    for r in issues:
        print(f"[{r['severity'].upper()}] {r['category']} (commit {r['location']}, {r['raw_context']})")
        print(f"  Message:    {r['text'].splitlines()[0]}")
        print(f"  Suggestion: {r['recommendation']}\n")
        
