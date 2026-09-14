import argparse
import ast
import json
import re
import sys


SEVERITY = {
    "SQL Injection": "High",
    "Command Injection": "High",
    "Hardcoded Secret": "High",
}

SARIF_RULE_IDS = {
    "SQL Injection": "sql-injection",
    "Command Injection": "command-injection",
    "Hardcoded Secret": "hardcoded-secret",
}

SARIF_SEVERITY_LEVELS = {
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


class BaseVisitor(ast.NodeVisitor):
    """Shared taint-tracking logic used by AST-based detectors."""

    vulnerability_type = "unknown"
    requires_ast = True

    def __init__(self, source_lines):
        self.findings = []
        self.tainted_vars = set()
        self.source_lines = source_lines

    @classmethod
    def run(cls, source, source_lines, tree):
        visitor = cls(source_lines)
        visitor.visit(tree)
        return visitor.findings

    def visit_FunctionDef(self, node):
        outer_tainted = self.tainted_vars
        self.tainted_vars = set()
        self.generic_visit(node)
        self.tainted_vars = outer_tainted

    def visit_Assign(self, node):
        if self._is_unsafe_string_build(node.value) or self._is_tainted_name(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def _is_unsafe_string_build(self, node):
        return isinstance(node, (ast.BinOp, ast.JoinedStr))

    def _is_tainted_name(self, node):
        return isinstance(node, ast.Name) and node.id in self.tainted_vars

    def _record_finding(self, node):
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        snippet_lines = self.source_lines[start - 1:end]
        snippet = " ".join(line.strip() for line in snippet_lines)
        self.findings.append({
            "type": self.vulnerability_type,
            "line": start,
            "snippet": snippet,
            "severity": SEVERITY.get(self.vulnerability_type, "Medium"),
        })


class SQLInjectionVisitor(BaseVisitor):
    vulnerability_type = "SQL Injection"

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                if self._is_unsafe_string_build(arg) or self._is_tainted_name(arg):
                    self._record_finding(node)
        self.generic_visit(node)


class CommandInjectionVisitor(BaseVisitor):
    vulnerability_type = "Command Injection"

    UNSAFE_FUNCS = {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "call"),
        ("subprocess", "run"),
        ("subprocess", "Popen"),
    }

    def visit_Call(self, node):
        if self._is_unsafe_call(node):
            if node.args:
                arg = node.args[0]
                if self._is_unsafe_string_build(arg) or self._is_tainted_name(arg):
                    self._record_finding(node)
        self.generic_visit(node)

    def _is_unsafe_call(self, node):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr
            return (module, func) in self.UNSAFE_FUNCS
        return False


class SecretDetector:
    """Regex-based detector for hardcoded credentials. Not AST-based."""

    vulnerability_type = "Hardcoded Secret"
    requires_ast = False

    PATTERNS = {
        "AWS Access Key": r"AKIA[A-Z0-9]{16}",
        "Stripe Live Key": r"sk_live_[a-zA-Z0-9]{24,}",
        "Generic API Key Assignment": r"(?i)(api[_-]?key|secret[_-]?key)\s*=\s*[\"'][a-zA-Z0-9_\-]{16,}[\"']",
        "Private Key Header": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    }

    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.findings = []

    @classmethod
    def run(cls, source, source_lines, tree):
        detector = cls(source_lines)
        return detector.scan()

    def scan(self):
        for i, line in enumerate(self.source_lines, start=1):
            for label, pattern in self.PATTERNS.items():
                if re.search(pattern, line):
                    self.findings.append({
                        "type": self.vulnerability_type,
                        "line": i,
                        "snippet": line.strip(),
                        "severity": "High",
                    })
        return self.findings


def to_sarif(filepath, results):
    """Convert scanner findings into a SARIF 2.1.0 JSON structure."""
    sarif_results = []
    for r in results:
        sarif_results.append({
            "ruleId": SARIF_RULE_IDS.get(r["type"], "unknown"),
            "level": SARIF_SEVERITY_LEVELS.get(r["severity"], "warning"),
            "message": {"text": f"{r['type']} detected: {r['snippet']}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": filepath},
                        "region": {"startLine": r["line"]},
                    }
                }
            ],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semantic-code-vuln-spotting",
                        "informationUri": "https://github.com/vishnu17306/semantic-code-vuln-spotting",
                        "version": "0.1.0",
                        "rules": [
                            {"id": rule_id, "name": name}
                            for name, rule_id in SARIF_RULE_IDS.items()
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }


class VulnerabilityScanner:
    """Runs all registered detectors over a single file.

    Every detector class must define:
      - requires_ast: bool
      - run(cls, source, source_lines, tree) -> list[dict]
    This uniform interface is what lets rule-based, regex-based,
    and (later) ML-based detectors plug in interchangeably.
    """

    AVAILABLE_CHECKS = {
        "sqli": SQLInjectionVisitor,
        "cmdi": CommandInjectionVisitor,
        "secrets": SecretDetector,
    }

    def __init__(self, checks=None):
        if checks is None:
            self.detector_classes = list(self.AVAILABLE_CHECKS.values())
        else:
            self.detector_classes = [self.AVAILABLE_CHECKS[c] for c in checks]

    def scan(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
        except UnicodeDecodeError:
            print(f"Skipping {filepath}: invalid encoding detected.")
            return []
        except IOError as e:
            print(f"Skipping {filepath}: could not read file ({e}).")
            return []

        source_lines = source.splitlines()

        needs_ast = any(cls.requires_ast for cls in self.detector_classes)
        tree = None
        if needs_ast:
            try:
                tree = ast.parse(source)
            except SyntaxError as e:
                print(f"Skipping {filepath}: syntax error ({e}).")
                return []

        results = []
        for detector_cls in self.detector_classes:
            results.extend(detector_cls.run(source, source_lines, tree))

        seen = set()
        deduped = []
        for r in sorted(results, key=lambda x: x["line"]):
            key = (r["line"], r["type"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        return deduped

    def report(self, filepath, output_format="text"):
        results = self.scan(filepath)

        if output_format == "sarif":
            print(json.dumps(to_sarif(filepath, results), indent=2))
            return

        if not results:
            print(f"No issues found in {filepath}")
            return

        print(f"Findings in {filepath}:\n")
        for r in results:
            print(f"  [{r['severity']}] {r['type']} — line {r['line']}")
            print(f"    {r['snippet']}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Static vulnerability scanner for Python code (AST-based)."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the Python file to scan",
    )
    parser.add_argument(
        "--checks",
        default="sqli,cmdi,secrets",
        help="Comma-separated list of checks to run (default: sqli,cmdi,secrets)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    checks = [c.strip() for c in args.checks.split(",")]

    invalid = [c for c in checks if c not in VulnerabilityScanner.AVAILABLE_CHECKS]
    if invalid:
        print(f"Unknown check(s): {', '.join(invalid)}")
        print(f"Available checks: {', '.join(VulnerabilityScanner.AVAILABLE_CHECKS.keys())}")
        sys.exit(1)

    scanner = VulnerabilityScanner(checks=checks)
    scanner.report(args.file, output_format=args.format)