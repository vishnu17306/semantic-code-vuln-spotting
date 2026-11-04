import csv
import random
import re
import sys
from pathlib import Path

from comment_extractor import extract_from_file

MARKER = re.compile(r"\b(TODO|FIXME|BUG|HACK|XXX)\b", re.IGNORECASE)
RISK = re.compile(
    r"(security|vulnerab|inject|exploit|unsafe|insecure|attack|malicious|"
    r"crash|segfault|leak|race condition|deadlock|corrupt|data loss|overflow|"
    r"password|credential|untrusted|sanitiz)",
    re.IGNORECASE,
)
SKIP = re.compile(
    r"(copyright|license|noqa|pylint|pragma|type:\s*ignore|coding[:=]|!/usr/bin|flake8|mypy)",
    re.IGNORECASE,
)
QUOTAS = {"marker": 70, "risk": 50, "other": 30}


def collect(roots):
    seen = set()
    groups = {"marker": [], "risk": [], "other": []}
    for root in roots:
        if not Path(root).is_dir():
            print(f"Skipping missing folder: {root}")
            continue
        for path in Path(root).rglob("*.py"):
            try:
                if path.stat().st_size > 500_000:
                    continue
                records = extract_from_file(str(path))
            except Exception:
                continue
            for r in records:
                text = r["text"]
                key = text.lower()
                if len(text.split()) < 4 or SKIP.search(text) or key in seen:
                    continue
                seen.add(key)
                if RISK.search(text):
                    group = "risk"
                elif MARKER.search(text):
                    group = "marker"
                else:
                    group = "other"
                groups[group].append(
                    {"group": group, "file": str(path), "line": r["location"], "text": text}
                )
    return groups


if __name__ == "__main__":
    roots = sys.argv[1:]
    if not roots:
        print("Usage: python3 make_gold_set.py <folder> [<folder> ...]")
        sys.exit(1)

    random.seed(42)
    groups = collect(roots)
    picked = []
    for name, rows in groups.items():
        k = min(QUOTAS[name], len(rows))
        print(f"{name:>7}: {len(rows)} candidates, sampling {k}")
        picked += random.sample(rows, k)
    random.shuffle(picked)

    with open("gold_set.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "text", "label", "group", "file", "line"])
        for i, row in enumerate(picked, start=1):
            writer.writerow([i, row["text"], "", row["group"], row["file"], row["line"]])

    print(f"Wrote {len(picked)} rows to gold_set.csv. Fill in the 'label' column.")
