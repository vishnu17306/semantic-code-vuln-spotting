from triage import DEFAULT_EXCLUDES, filter_and_sort, link_findings, make_issue, scan_files


def test_comment_and_scanner_findings_are_linked(tmp_path):
    src = (
        "def get_user(cursor, user_id):\n"
        "    # FIXME: SQL injection here\n"
        '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    )
    (tmp_path / "app.py").write_text(src)
    issues, files, skipped = scan_files(tmp_path, DEFAULT_EXCLUDES)
    link_findings(issues)
    comment = [i for i in issues if i["source"] == "comment"]
    scanner = [i for i in issues if i["source"] == "scanner"]
    assert len(comment) == 1 and comment[0]["severity"] == "critical"
    assert len(scanner) == 1 and scanner[0]["category"] == "SQL Injection"
    assert comment[0]["also_flagged_by"] and scanner[0]["also_flagged_by"]


def test_excluded_folders_are_skipped(tmp_path):
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "lib.py").write_text("# TODO: fix this later\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    issues, files, skipped = scan_files(tmp_path, DEFAULT_EXCLUDES)
    assert files == 1
    assert issues == []


def test_min_severity_filters_and_sorts():
    low = make_issue("comment", "low", "cleanup", "tidy", "tidy up", file="a.py", line=1)
    crit = make_issue("scanner", "critical", "SQL Injection", "code", "fix", file="a.py", line=9)
    assert filter_and_sort([low, crit], "high") == [crit]
    assert filter_and_sort([low, crit], "low")[0] is crit


def test_unparseable_file_is_counted_not_fatal(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n    # TODO: finish this\n")
    issues, files, skipped = scan_files(tmp_path, DEFAULT_EXCLUDES)
    assert files == 1
    assert skipped == 1


def test_findings_three_lines_apart_are_not_linked():
    comment = make_issue("comment", "low", "incomplete", "TODO: later", "do it", file="a.py", line=14)
    scanner = make_issue("scanner", "high", "Path Traversal", "code", "fix", file="a.py", line=11)
    link_findings([comment, scanner])
    assert comment["also_flagged_by"] == []
    assert scanner["also_flagged_by"] == []
