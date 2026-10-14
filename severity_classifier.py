import argparse
import re

from comment_extractor import extract_from_file

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# (regex, severity, category), checked against the comment text
KEYWORD_RULES = [
    (r"\b(sql injection|injection|vulnerab\w*|exploit\w*|attacker\w*|xss|csrf|insecure|security)\b",
     "critical", "security"),
    (r"\b(data loss|corrupt\w*)\b", "critical", "data_loss"),
    (r"\b(password\w*|credential\w*|secret\w*|api key)\b", "high", "security"),
    (r"\b(crash\w*|broken|breaks|fails|failing|exception|race condition|deadlock|memory leak|wrong|incorrect|urgent)\b",
     "high", "bug"),
    (r"\b(error handling|handle|unhandled|edge case|validat\w*|missing|timeout)\b",
     "medium", "error_handling"),
    (r"\b(slow|performance|inefficient|optimi[sz]e|bottleneck)\b", "medium", "performance"),
    (r"\b(deprecated|outdated|legacy)\b", "medium", "deprecated"),
    (r"\b(cleanup|clean up|rename|refactor|typo|style|formatting|nit|later|tidy)\b",
     "low", "cleanup"),
]

# Markers set a minimum severity; keywords can raise it
MARKER_PATTERN = r"\s*(TODO|FIXME|BUG|HACK|XXX)\b"
MARKERS = {
    "BUG": ("high", "bug"),
    "FIXME": ("medium", "bug"),
    "XXX": ("medium", "bug"),
    "HACK": ("medium", "workaround"),
    "TODO": ("low", "incomplete"),
}

RECOMMENDATIONS = {
    "security": "Treat this as a security risk: validate or sanitize user input, use parameterized queries, and keep secrets out of the code.",
    "data_loss": "Protect data first: add a backup, a confirmation step, or a transaction before this operation.",
    "bug": "Reproduce the problem with a small test, then fix the cause and keep the test.",
    "error_handling": "Add a check for this case (for example empty or missing input) and return a clear error instead of failing.",
    "performance": "Measure first, then speed up the slow part, for example with caching or a more efficient loop.",
    "deprecated": "Replace this with the current recommended approach and remove the old code.",
    "workaround": "Replace this workaround with a proper fix, and note why it was needed.",
    "cleanup": "Tidy this up: simplify or rename it so the code is easier to read.",
    "incomplete": "Finish this task or open a tracking issue so it doesn't get forgotten.",
}


def classify(record):
    """Return the record plus severity/category/recommendation, or None if it isn't an issue."""
    text = record["text"]
    candidates = []

    for pattern, severity, category in KEYWORD_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            candidates.append((severity, category))

    marker = re.match(MARKER_PATTERN, text, re.IGNORECASE)
    if marker:
        candidates.append(MARKERS[marker.group(1).upper()])

    if not candidates:
        return None

    # Highest severity wins; on a tie the keyword (more specific) beats the marker
    severity, category = max(candidates, key=lambda c: SEVERITY_ORDER[c[0]])

    result = dict(record)
    result["severity"] = severity
    result["category"] = category
    result["recommendation"] = RECOMMENDATIONS[category]
    return result


def classify_all(records):
    issues = [r for r in (classify(rec) for rec in records) if r]
    return sorted(issues, key=lambda r: (-SEVERITY_ORDER[r["severity"]], r["location"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Triage developer comments by severity.")
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    issues = classify_all(extract_from_file(args.file))
    if not issues:
        print("No issues found in comments.")
    for r in issues:
        print(f"[{r['severity'].upper()}] {r['category']} (line {r['location']})")
        print(f"  Comment:    {r['text']}")
        print(f"  Suggestion: {r['recommendation']}\n")
        