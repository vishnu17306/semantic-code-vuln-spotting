from scanner import VulnerabilityScanner


def scan(tmp_path, code):
    f = tmp_path / "sample.py"
    f.write_text(code)
    return VulnerabilityScanner(checks=["pathtraversal"]).scan(str(f))


def lines(results):
    return [r["line"] for r in results]


# --- Cases the detector should flag ---

def test_cvefixes_style_path_join_is_flagged(tmp_path):
    # Modeled on the first CVEFixes example: a request parameter is joined
    # onto a base directory without any check.
    code = (
        "import os\n"
        "def browse(job_id, path):\n"
        "    job_base_dir = '/data/jobs'\n"
        "    abs_path = os.path.join(job_base_dir, path)\n"
        "    return abs_path\n"
    )
    results = scan(tmp_path, code)
    assert lines(results) == [4]
    assert results[0]["type"] == "Path Traversal"


def test_parameter_passed_to_open_is_flagged(tmp_path):
    code = "def read_file(filename):\n    return open(filename)\n"
    assert lines(scan(tmp_path, code)) == [2]


def test_fstring_path_is_flagged(tmp_path):
    code = "def serve(name):\n    return open(f'/static/{name}')\n"
    assert lines(scan(tmp_path, code)) == [2]


def test_tarfile_open_with_parameter_is_flagged(tmp_path):
    code = "import tarfile\ndef unpack(archive):\n    return tarfile.open(archive)\n"
    assert lines(scan(tmp_path, code)) == [3]


def test_taint_flows_through_string_building(tmp_path):
    code = (
        "def serve(name):\n"
        "    full_path = '/static/' + name\n"
        "    return open(full_path)\n"
    )
    assert lines(scan(tmp_path, code)) == [3]


# --- Cases the detector should leave alone ---

def test_hardcoded_path_is_not_flagged(tmp_path):
    code = "def read_config():\n    return open('/etc/myapp/config.yaml')\n"
    assert scan(tmp_path, code) == []


def test_taint_does_not_leak_between_functions(tmp_path):
    code = (
        "def first(path):\n"
        "    return path\n"
        "\n"
        "def second():\n"
        "    path = 'fixed.txt'\n"
        "    return open(path)\n"
    )
    assert scan(tmp_path, code) == []


# --- Known limitations, written down so they are visible and tracked ---

def test_taint_is_lost_through_call_results_known_gap(tmp_path):
    # The value returned by os.path.join is not tracked, so the open() on
    # line 4 is missed. If this is fixed later, update the expected list.
    code = (
        "import os\n"
        "def serve(name):\n"
        "    full_path = os.path.join('/static', name)\n"
        "    return open(full_path)\n"
    )
    assert lines(scan(tmp_path, code)) == [3]


def test_validated_path_is_still_flagged_known_limitation(tmp_path):
    # No sanitization awareness: a checked path is reported anyway.
    code = (
        "def serve(name):\n"
        "    if '..' in name:\n"
        "        raise ValueError('bad path')\n"
        "    return open(name)\n"
    )
    assert lines(scan(tmp_path, code)) == [4]


def test_async_function_parameters_are_not_tracked_known_gap(tmp_path):
    # async handlers (common in web frameworks) are not seeded with taint.
    code = "async def handler(path):\n    return open(path)\n"
    assert scan(tmp_path, code) == []
