import ast
import sys


class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.tainted_vars = set()  # tainted vars for the CURRENT scope only

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

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                if self._is_unsafe_string_build(arg) or self._is_tainted_name(arg):
                    self.findings.append(node.lineno)
        self.generic_visit(node)

    def _is_unsafe_string_build(self, node):
        if isinstance(node, ast.BinOp):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        return False

    def _is_tainted_name(self, node):
        return isinstance(node, ast.Name) and node.id in self.tainted_vars


def analyze_file(filepath):
    with open(filepath, "r") as f:
        source = f.read()

    tree = ast.parse(source)
    visitor = SQLInjectionVisitor()
    visitor.visit(tree)

    if visitor.findings:
        print(f"Potential SQL injection found in {filepath}:")
        for line in sorted(set(visitor.findings)):
            print(f"  - line {line}")
    else:
        print(f"No issues found in {filepath}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detector.py <filepath>")
        sys.exit(1)

    analyze_file(sys.argv[1])