import csv
import random

SOURCE = "gold_set_frozen.csv"
PER_LABEL = {"none": 10, "low": 10, "medium": 10, "high": 10}  # critical rows join "high"
GUIDE = """LABELING GUIDE

You will see a short comment from real Python code, plus the few lines of code under it.
For each one, decide how serious the problem it describes is. Write exactly one word in
the "label" column:

  critical   a security hole, data loss or corruption, or a crash in a core path
  high       a real bug that users would hit today
  medium     missing edge-case handling, a performance problem, or important unfinished work
  low        cleanup, style, a typo, a "remove when version X is dropped" chore, a nice-to-have
  none       not an open issue: an explanation, documentation, something already fixed, or
             a test that only checks that something does NOT fail

Rules of thumb:
  - Does the comment point at a problem or a task? If it only explains what the code does
    or why, the label is none.
  - Check the tense. "Used to crash" or "was fixed" is none. "Crashes when..." is a problem.
  - Do not worry about being perfect. Decide quickly (about 20 seconds per comment).
  - Please do this on your own, without asking anyone or using any tool.
"""


def code_snippet(path, line, count=6):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return ""
    start = max(int(line) - 1, 0)
    return " | ".join(l.strip()[:100] for l in lines[start:start + count])


def main():
    with open(SOURCE, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["label"].strip()]

    random.seed(7)
    picked = []
    for label, k in PER_LABEL.items():
        pool = [r for r in rows if r["label"] == label]
        if label == "high":
            pool += [r for r in rows if r["label"] == "critical"]
        picked += random.sample(pool, min(k, len(pool)))
    random.shuffle(picked)

    with open("friend_set.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "comment", "code_under_it", "label"])
        for r in picked:
            writer.writerow([r["id"], r["text"], code_snippet(r["file"], r["line"]), ""])

    with open("friend_key.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "my_label"])
        for r in picked:
            writer.writerow([r["id"], r["label"]])

    with open("friend_guide.txt", "w", encoding="utf-8") as f:
        f.write(GUIDE)

    print(f"Wrote {len(picked)} rows to friend_set.csv (send this and friend_guide.txt).")
    print("friend_key.csv holds YOUR labels. Do not send it or open it until your friend is done.")


if __name__ == "__main__":
    main()
