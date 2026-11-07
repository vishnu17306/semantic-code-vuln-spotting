from comment_extractor import extract_inline_comments


def test_standalone_comment_extracted():
    results = extract_inline_comments("# TODO: fix this\nx = 1")
    assert len(results) == 1
    assert results[0]["text"] == "TODO: fix this"
    assert results[0]["location"] == 1


def test_trailing_comment_extracted():
    results = extract_inline_comments("x = 1  # FIXME: wrong value")
    assert len(results) == 1
    assert results[0]["raw_context"] == "x = 1  # FIXME: wrong value"


def test_hash_inside_string_is_not_a_comment():
    results = extract_inline_comments('url = "http://x.com/#anchor"')
    assert results == []


def test_empty_file_returns_nothing():
    assert extract_inline_comments("") == []


def test_broken_file_does_not_crash():
    extract_inline_comments("def broken(:\n    # still a comment\n")


def test_consecutive_comment_lines_are_merged():
    src = "# first part of the note\n# second part of the note\nx = 1"
    results = extract_inline_comments(src)
    assert len(results) == 1
    assert results[0]["text"] == "first part of the note second part of the note"
    assert results[0]["location"] == 1


def test_trailing_comments_are_not_merged():
    src = "x = 1  # one\ny = 2  # two"
    assert len(extract_inline_comments(src)) == 2
