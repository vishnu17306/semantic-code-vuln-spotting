import pytest
from scanner import VulnerabilityScanner


def run_scan(tmp_path, code, checks=None):
    """Helper: write code to a temp file and scan it."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    scanner = VulnerabilityScanner(checks=checks)
    return scanner.scan(str(f))


# --- SQL Injection: direct patterns ---

def test_sqli_concatenation_detected(tmp_path):
    code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    results = run_scan(tmp_path, code, checks=["sqli"])
    assert len(results) == 1
    assert results[0]["type"] == "SQL Injection"
    assert results[0]["line"] == 1


def test_sqli_fstring_detected(tmp_path):
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    results = run_scan(tmp_path, code, checks=["sqli"])
    assert len(results) == 1


def test_sqli_parameterized_query_is_safe(tmp_path):
    code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    results = run_scan(tmp_path, code, checks=["sqli"])
    assert len(results) == 0


# --- SQL Injection: taint tracking + scoping ---

def test_sqli_taint_tracking_indirect_variable(tmp_path):
    code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
'''
    results = run_scan(tmp_path, code, checks=["sqli"])
    assert len(results) == 1
    assert results[0]["line"] == 4


def test_sqli_scoping_does_not_leak_across_functions(tmp_path):
    code = '''
def build_unsafe(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def build_safe(order_id):
    query = "SELECT * FROM orders WHERE id = ?"
    cursor.execute(query, (order_id,))
'''
    results = run_scan(tmp_path, code, checks=["sqli"])
    assert len(results) == 1
    assert results[0]["line"] == 4  # only build_unsafe flagged


# --- Command Injection ---

def test_cmdi_os_system_detected(tmp_path):
    code = 'import os\nos.system("ping -c 1 " + hostname)'
    results = run_scan(tmp_path, code, checks=["cmdi"])
    assert len(results) == 1
    assert results[0]["type"] == "Command Injection"


def test_cmdi_safe_list_args_not_flagged(tmp_path):
    code = 'import subprocess\nsubprocess.run(["ping", "-c", "1", hostname])'
    results = run_scan(tmp_path, code, checks=["cmdi"])
    assert len(results) == 0


# --- Edge cases ---

def test_empty_file_produces_no_findings(tmp_path):
    results = run_scan(tmp_path, "")
    assert results == []


def test_whitespace_only_file_produces_no_findings(tmp_path):
    results = run_scan(tmp_path, "   \n\n   \n")
    assert results == []


def test_syntactically_invalid_file_returns_empty_results(tmp_path):
    code = "def broken(:\n    pass"
    results = run_scan(tmp_path, code)
    assert results == []


def test_checks_filter_restricts_detectors(tmp_path):
    code = '''
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
os.system("ping " + hostname)
'''
    sqli_only = run_scan(tmp_path, code, checks=["sqli"])
    assert len(sqli_only) == 1
    assert sqli_only[0]["type"] == "SQL Injection"
    