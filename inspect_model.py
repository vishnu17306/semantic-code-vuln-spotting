import joblib

model = joblib.load("severity_tfidf.joblib")
vectorizer = model.named_steps["tfidfvectorizer"]
clf = model.named_steps["logisticregression"]
features = vectorizer.get_feature_names_out()

print("Top 10 words/phrases the model associates with each severity:\n")
for i, label in enumerate(clf.classes_):
    top = clf.coef_[i].argsort()[-10:][::-1]
    print(f"{label:>9}: " + ", ".join(features[j] for j in top))

tests = [
    "this is NOT a security issue, just documenting the flow",
    "TODO: rename the password field to pwd",
    "works fine now, no longer crashes on empty input",
    "users keep complaining that checkout loses their cart",
    "FIXME: SQL injection here!",
    "BUG: crashes when the list is empty",
    "cleanup: rename this variable later",
    "typo in error message",
]

print("\nPredictions on code-comment style text:\n")
for text in tests:
    probs = model.predict_proba([text])[0]
    best = probs.argmax()
    print(f"{clf.classes_[best]:>9} ({probs[best]:.0%})  {text}")
