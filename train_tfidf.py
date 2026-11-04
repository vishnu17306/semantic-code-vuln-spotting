import joblib
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

from severity_classifier import classify

LEVELS = ["critical", "high", "medium", "low"]
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
df["text"] = df["Short Description"].fillna("").astype(str)
df["true"] = df["Severity Label"].map(LABEL_MAP)

train_df, test_df = train_test_split(
    df, test_size=0.2, stratify=df["true"], random_state=42
)


def keyword_predict(text):
    record = {"text": text, "source_type": "bug_report", "location": 0, "raw_context": ""}
    result = classify(record)
    return result["severity"] if result else "medium"


keyword_pred = test_df["text"].apply(keyword_predict)

model = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100000, sublinear_tf=True),
    LogisticRegression(max_iter=1000, class_weight="balanced"),
)
model.fit(train_df["text"], train_df["true"])
model_pred = model.predict(test_df["text"])

for name, pred in [("Keyword baseline", keyword_pred), ("TF-IDF + LogReg", model_pred)]:
    print(f"=== {name} ===")
    print(f"macro-F1: {f1_score(test_df['true'], pred, labels=LEVELS, average='macro'):.3f}")
    print(classification_report(test_df["true"], pred, labels=LEVELS, zero_division=0))

joblib.dump(model, "severity_tfidf.joblib")