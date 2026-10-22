import pandas as pd
from datasets import load_dataset
from sklearn.metrics import classification_report, confusion_matrix

from severity_classifier import classify

LEVELS = ["critical", "high", "medium", "low"]

# Bugzilla severity -> our four levels (a design choice, see notes)
LABEL_MAP = {
    "blocker": "critical",
    "critical": "critical",
    "major": "high",
    "normal": "medium",
    "minor": "low",
    "trivial": "low",
}

ds = load_dataset("AliArshad/Bugzilla_Eclipse_Bug_Reports_Dataset")
df = ds["train"].to_pandas()
df["Short Description"] = df["Short Description"].fillna("").astype(str)
df["true"] = df["Severity Label"].map(LABEL_MAP)


def predict(text):
    record = {"text": text, "source_type": "bug_report", "location": 0, "raw_context": ""}
    result = classify(record)
    return result["severity"] if result else None


df["raw_pred"] = df["Short Description"].apply(predict)
coverage = df["raw_pred"].notna().mean()
# No keyword fired -> fall back to "medium" (the majority class)
df["pred"] = df["raw_pred"].fillna("medium")

print(f"Rows: {len(df)}")
print(f"Baseline fired on {coverage:.1%} of reports (the rest defaulted to medium)")
print(f"Always-'medium' accuracy for reference: {(df['true'] == 'medium').mean():.1%}\n")

print(classification_report(df["true"], df["pred"], labels=LEVELS, zero_division=0))

print("Confusion matrix (rows = true, columns = predicted):")
print(pd.DataFrame(
    confusion_matrix(df["true"], df["pred"], labels=LEVELS),
    index=LEVELS, columns=LEVELS,
))