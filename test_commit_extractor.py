import subprocess

from commit_extractor import extract_commit_messages


def make_repo(tmp_path, messages):
    def git(*args):
        subprocess.run(
            ["git", "-C", str(tmp_path),
             "-c", "user.name=tester", "-c", "user.email=t@example.com", *args],
            check=True, capture_output=True,
        )

    git("init")
    for i, msg in enumerate(messages):
        (tmp_path / f"f{i}.txt").write_text(str(i))
        git("add", ".")
        git("commit", "-m", msg)


def test_commit_messages_extracted(tmp_path):
    make_repo(tmp_path, ["first commit", "Fix crash on empty input"])
    records = extract_commit_messages(str(tmp_path))
    assert len(records) == 2
    assert records[0]["text"] == "Fix crash on empty input"  # newest first
    assert records[0]["source_type"] == "commit_message"


def test_record_has_unified_shape(tmp_path):
    make_repo(tmp_path, ["only commit"])
    record = extract_commit_messages(str(tmp_path))[0]
    assert set(record) == {"text", "source_type", "location", "raw_context"}


def test_not_a_git_repo_returns_empty(tmp_path):
    assert extract_commit_messages(str(tmp_path)) == []