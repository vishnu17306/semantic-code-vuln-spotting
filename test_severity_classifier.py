from severity_classifier import classify


def rec(text):
    return {"text": text, "source_type": "inline_comment", "location": 1, "raw_context": ""}


def test_sql_injection_comment_is_critical():
    assert classify(rec("FIXME: SQL injection here!"))["severity"] == "critical"


def test_crash_bug_is_high():
    assert classify(rec("BUG: crashes when the list is empty"))["severity"] == "high"


def test_cleanup_is_low():
    assert classify(rec("cleanup: rename this variable later"))["severity"] == "low"


def test_keyword_raises_marker_severity():
    # TODO alone is low, but "handle" lifts it to medium
    result = classify(rec("TODO: handle empty input"))
    assert result["severity"] == "medium"
    assert result["category"] == "error_handling"


def test_plain_comment_is_not_an_issue():
    assert classify(rec("returns the user's name")) is None


def test_every_issue_gets_a_recommendation():
    assert classify(rec("TODO: add tests"))["recommendation"]