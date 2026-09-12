import argparse
import ast
import sys


SEVERITY = {
    "SQL Injection": "High",
    "Command Injection": "High",
}


class BaseVisitor(ast.NodeVisitor):
    """Shared taint-tracking logic used by all detectors."""

    vulnerability_type = "unknown"

    def __init__(self, source_lines):
        self.findings = []
        self.tainted_vars = set()
        self.source_lines = source_lines

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


class VulnerabilityScanner:
    """Runs all registered detectors over a single file's AST."""

    AVAILABLE_CHECKS = {
        "sqli": SQLInjectionVisitor,
        "cmdi": CommandInjectionVisitor,
    }

    def __init__(self, checks=None):
        if checks is None:
            self.detector_classes = list(self.AVAILABLE_CHECKS.values())
        else:
            self.detector_classes = [self.AVAILABLE_CHECKS[c] for c in checks]

    def scan(self, filepath):
        with open(filepath, "r") as f:
            source = f.read()

        source_lines = source.splitlines()
        tree = ast.parse(source)
        results = []

        for detector_cls in self.detector_classes:
            visitor = detector_cls(source_lines)
            visitor.visit(tree)
            results.extend(visitor.findings)

        # Dedupe in case multiple detectors flag the same line
        seen = set()
        deduped = []
        for r in sorted(results, key=lambda x: x["line"]):
            key = (r["line"], r["type"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        return deduped

    def report(self, filepath):
        results = self.scan(filepath)

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
        default="sqli,cmdi",
        help="Comma-separated list of checks to run (default: sqli,cmdi)",
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
    scanner.report(args.file)