import csv

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

from severity_classifier import classify

LEVELS = ["critical", "high", "medium", "low"]

with open("gold_set.csv", newline="", encoding="utf-8") as f:
    rows = [r for r in csv.DictReader(f) if r["label"].strip()]

texts = [r["text"] for r in rows]
truth = [r["label"].strip().lower() for r in rows]
print(f"Scoring {len(rows)} labeled comments.\n")

model = joblib.load("severity_tfidf.joblib")
model_pred = list(model.predict(texts))


def keyword_label(text):
    record = {"text": text, "source_type": "inline_comment", "location": 0, "raw_context": ""}
    result = classify(record)
    return result["severity"] if result else None


kw_raw = [keyword_label(t) for t in texts]

# ---- Part 1: is this comment an issue at all? (none vs. everything else)
is_issue = [t != "none" for t in truth]
kw_fired = [p is not None for p in kw_raw]
tp = sum(1 for a, b in zip(is_issue, kw_fired) if a and b)
fp = sum(1 for a, b in zip(is_issue, kw_fired) if (not a) and b)
fn = sum(1 for a, b in zip(is_issue, kw_fired) if a and (not b))
precision = tp / (tp + fp) if tp + fp else 0.0
recall = tp / (tp + fn) if tp + fn else 0.0
share = sum(is_issue) / len(is_issue)

print("PART 1: is the comment an issue? (keyword rules firing = 'issue')")
print(f"  real issues in gold set: {sum(is_issue)} of {len(is_issue)} ({share:.0%})")
print(f"  keyword rules: precision {precision:.2f}, recall {recall:.2f}")
print(f"  'everything is an issue' baseline: precision {share:.2f}, recall 1.00")
print("  trained model: has no 'none' class, so it can't answer this question yet\n")

# ---- Part 2: severity, on comments that really are issues
idx = [i for i, t in enumerate(truth) if t != "none"]
y_true = [truth[i] for i in idx]
y_kw = [kw_raw[i] or "medium" for i in idx]  # no keyword -> default to medium
y_model = [model_pred[i] for i in idx]
present = [lab for lab in LEVELS if lab in y_true]

print(f"PART 2: severity on the {len(idx)} real issues")
print("  true label counts:", {lab: y_true.count(lab) for lab in present})
print(f"  always-'medium' accuracy for reference: {y_true.count('medium') / len(y_true):.1%}\n")

for name, pred in [("Keyword rules", y_kw), ("TF-IDF model", y_model)]:
    macro = f1_score(y_true, pred, labels=present, average="macro", zero_division=0)
    print(f"=== {name}: accuracy {accuracy_score(y_true, pred):.1%}, macro-F1 {macro:.3f}")
    print(classification_report(y_true, pred, labels=present, zero_division=0))
    print("Confusion matrix (rows = true, columns = predicted):")
    print("          " + "".join(f"{lab:>10}" for lab in present))
    matrix = confusion_matrix(y_true, pred, labels=present)
    for lab, row in zip(present, matrix):
        print(f"{lab:>10}" + "".join(f"{v:>10}" for v in row))
    print()


def show(title, cond, limit=5):
    print(title)
    shown = 0
    for i in idx:
        if cond(i):
            print(f"  [{truth[i]}] keyword={kw_raw[i] or 'medium'} model={model_pred[i]} | {texts[i][:90]}")
            shown += 1
            if shown == limit:
                break
    if shown == 0:
        print("  (none)")
    print()


show("Model right, keyword rules wrong:",
     lambda i: model_pred[i] == truth[i] and (kw_raw[i] or "medium") != truth[i])
show("Keyword rules right, model wrong:",
     lambda i: (kw_raw[i] or "medium") == truth[i] and model_pred[i] != truth[i])
