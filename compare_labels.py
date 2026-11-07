import csv
import sys
from collections import Counter

from sklearn.metrics import cohen_kappa_score

VALID = {"critical", "high", "medium", "low", "none"}
ALIASES = {"c": "critical", "h": "high", "m": "medium", "l": "low", "n": "none"}


def load(path, column):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["id"]: r for r in csv.DictReader(f)}, column


def main():
    friend_path = sys.argv[1] if len(sys.argv) > 1 else "friend_set_filled.csv"
    mine, _ = load("friend_key.csv", "my_label")
    theirs, _ = load(friend_path, "label")

    pairs, invalid, missing = [], [], 0
    for id_, row in theirs.items():
        label = row["label"].strip().lower()
        label = ALIASES.get(label, label)
        if not label:
            missing += 1
            continue
        if label not in VALID:
            invalid.append((id_, row["label"]))
            continue
        if id_ in mine:
            pairs.append((id_, mine[id_]["my_label"], label, row.get("comment", "")))

    if invalid:
        print(f"Ignored {len(invalid)} rows with unrecognized labels: {invalid[:5]}")
    if missing:
        print(f"{missing} rows were left blank and are not counted.")
    if len(pairs) < 2:
        print("Not enough labeled rows to compare.")
        return

    a = [p[1] for p in pairs]
    b = [p[2] for p in pairs]
    agree = sum(1 for x, y in zip(a, b) if x == y)
    print(f"Compared {len(pairs)} comments.")
    print(f"Exact agreement: {agree}/{len(pairs)} = {agree / len(pairs):.0%}")
    print(f"Cohen's kappa: {cohen_kappa_score(a, b):.2f}  (0 = chance level, 1 = perfect)")

    issue_a = [x != "none" for x in a]
    issue_b = [y != "none" for y in b]
    same = sum(1 for x, y in zip(issue_a, issue_b) if x == y)
    print(f"Agreement on 'is it an issue at all?': {same}/{len(pairs)} = {same / len(pairs):.0%}")

    labels = ["critical", "high", "medium", "low", "none"]
    counts = Counter(zip(a, b))
    print("\nRows = your label, columns = friend's label:")
    print(f"{'':>10}" + "".join(f"{lab:>10}" for lab in labels))
    for x in labels:
        print(f"{x:>10}" + "".join(f"{counts[(x, y)]:>10}" for y in labels))

    print("\nDisagreements (id | you | friend | comment):")
    for id_, x, y, text in pairs:
        if x != y:
            print(f"  {id_} | {x} | {y} | {text[:80]}")


if __name__ == "__main__":
    main()
