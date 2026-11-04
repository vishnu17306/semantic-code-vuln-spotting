import csv
import os
import sys
import textwrap
from collections import Counter

CSV_PATH = "gold_set.csv"
KEYS = {"c": "critical", "h": "high", "m": "medium", "l": "low", "n": "none"}


def load():
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return reader.fieldnames, list(reader)


def save(fieldnames, rows):
    tmp = CSV_PATH + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, CSV_PATH)


def show_code(path, line, count=6):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return
    start = max(int(line) - 1, 0)
    for n in range(start, min(start + count, len(lines))):
        print(f"  {n + 1:>5} | {lines[n][:100]}")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    only_group = sys.argv[2] if len(sys.argv) > 2 else None
    fieldnames, rows = load()

    counts = Counter((r["group"], r["label"]) for r in rows)
    labels = ["critical", "high", "medium", "low", "none"]
    print("Labels per bucket:")
    print(f"{'':>8}" + "".join(f"{lab:>10}" for lab in labels))
    for group in ["marker", "risk", "other"]:
        print(f"{group:>8}" + "".join(f"{counts[(group, lab)]:>10}" for lab in labels))

    if not target:
        print("\nTo re-check labels, run: python3 review_labels.py medium other")
        return

    todo = [
        r for r in rows
        if r["label"] == target and (only_group is None or r["group"] == only_group)
    ]
    print(f"\nRe-checking {len(todo)} rows currently labeled '{target}'.")
    print("Press Enter to keep the label, or type c/h/m/l/n to change it, q to quit.")

    for k, r in enumerate(todo, start=1):
        print("-" * 78)
        print(f"[{k}/{len(todo)}] id {r['id']}   currently: {r['label']}")
        print(textwrap.fill(r["text"], width=76, initial_indent="  ", subsequent_indent="  "))
        print("  File: " + r["file"].replace("venv/lib/python3.13/site-packages/", ""))
        print("  Code at that spot:")
        show_code(r["file"], r["line"])
        answer = input("Keep (Enter) or change [c/h/m/l/n, q=quit]: ").strip().lower()
        if answer == "q":
            break
        if answer in KEYS:
            r["label"] = KEYS[answer]
            save(fieldnames, rows)
    print("Done.")


if __name__ == "__main__":
    main()
