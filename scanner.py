import ast
import sys


class BaseVisitor(ast.NodeVisitor):
    """Shared taint-tracking logic used by all detectors."""

    vulnerability_type = "unknown"

    def __init__(self):
        self.findings = []
        self.tainted_vars = set()

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


class SQLInjectionVisitor(BaseVisitor):
    vulnerability_type = "SQL Injection"

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                if self._is_unsafe_string_build(arg) or self._is_tainted_name(arg):
                    self.findings.append(node.lineno)
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
                    self.findings.append(node.lineno)
        self.generic_visit(node)

    def _is_unsafe_call(self, node):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr
            return (module, func) in self.UNSAFE_FUNCS
        return False


class VulnerabilityScanner:
    """Runs all registered detectors over a single file's AST."""

    def __init__(self):
        self.detector_classes = [SQLInjectionVisitor, CommandInjectionVisitor]

    def scan(self, filepath):
        with open(filepath, "r") as f:
            source = f.read()

        tree = ast.parse(source)
        results = []

        for detector_cls in self.detector_classes:
            visitor = detector_cls()
            visitor.visit(tree)
            for line in sorted(set(visitor.findings)):
                results.append({
                    "type": visitor.vulnerability_type,
                    "line": line,
                })

        return results

    def report(self, filepath):
        results = self.scan(filepath)

        if not results:
            print(f"No issues found in {filepath}")
            return

        print(f"Findings in {filepath}:")
        for r in sorted(results, key=lambda x: x["line"]):
            print(f"  - line {r['line']}: {r['type']}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <filepath>")
        sys.exit(1)

    scanner = VulnerabilityScanner()
    scanner.report(sys.argv[1])