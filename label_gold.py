import csv
import os
import textwrap

CSV_PATH = "gold_set.csv"
KEYS = {"c": "critical", "h": "high", "m": "medium", "l": "low", "n": "none"}

HELP = """
  c = critical   security hole, data loss/corruption, crash in a core path
  h = high       real bug that users would hit
  m = medium     missing edge-case handling, performance, important unfinished work
  l = low        cleanup, style, typo, nice-to-have
  n = none       not an open issue (explanation, documentation, already fixed)
  s = skip for now     b = go back one     q = save and quit
"""


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


def show_code(path, line, count=8):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        print("  (could not read the source file)")
        return
    start = max(int(line) - 1, 0)
    for n in range(start, min(start + count, len(lines))):
        print(f"  {n + 1:>5} | {lines[n][:110]}")


def main():
    fieldnames, rows = load()
    total = len(rows)
    i = next((k for k, r in enumerate(rows) if not r["label"].strip()), total)
    print(HELP)

    while i < total:
        row = rows[i]
        done = sum(1 for r in rows if r["label"].strip())
        print("=" * 78)
        print(f"Comment {i + 1} of {total}   (labeled so far: {done})")
        print("=" * 78)
        print(textwrap.fill(row["text"], width=76, initial_indent="  ", subsequent_indent="  "))
        print(f"\n  File: {row['file']}  (line {row['line']})")
        print("  Code around it:")
        show_code(row["file"], row["line"])
        if row["label"].strip():
            print(f"\n  Current label: {row['label']}")

        try:
            answer = input("\nYour label [c/h/m/l/n, s=skip, b=back, q=quit, ?=help]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if answer in KEYS:
            row["label"] = KEYS[answer]
            save(fieldnames, rows)
            i += 1
        elif answer == "s":
            i += 1
        elif answer == "b":
            i = max(i - 1, 0)
        elif answer == "q":
            break
        elif answer == "?":
            print(HELP)
        else:
            print("  Please type one of: c h m l n s b q")

    counts = {}
    for r in rows:
        key = r["label"].strip() or "(unlabeled)"
        counts[key] = counts.get(key, 0) + 1
    print("\nSummary:")
    for key, n in sorted(counts.items()):
        print(f"  {key:>12}: {n}")
    if "(unlabeled)" in counts:
        print("\nRun this script again to continue where you left off.")
    else:
        print("\nAll rows labeled. Nice work.")


if __name__ == "__main__":
    main()
