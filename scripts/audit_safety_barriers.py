#!/usr/bin/env python3
"""
Static AST & Keyword Auditor for Milestone 1.

Scans client/ and server/ production code to guarantee zero references to forbidden
destructive endpoints or mutating methods. Exits with 0 on pass, 1 on violation.
"""

from __future__ import annotations

import ast
import os
import sys
from typing import List, Tuple

FORBIDDEN_STRINGS: List[str] = [
    "deleteClientEquipment",
    "removeLock",
    "bindLock",
    "clearFingerprints",
    "clearAllFingerprints",
    "deleteFingerprint",
    "modifyFingerprint",
    "resetLock",
    "alterPassword",
    "findbackPassword",
    "clearOrCoverClientEquipmentAuth",
    "ttlockResetKeyboardPwd",
    "ttlockUpdateSpecialValue",
    "deleteClientEquipmentAuthAccount",
    "deleteAutoAdapt",
    "saveAutoAdapt",
]

TARGET_DIRS: List[str] = ["client", "server"]
EXCLUDED_FILES: List[str] = ["safety.py", "__init__.py"]


def check_ast_for_violations(file_path: str, content: str) -> List[Tuple[str, int, str, str]]:
    """Inspects AST string literals and function calls for forbidden strings."""
    violations: List[Tuple[str, int, str, str]] = []
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError as e:
        print(f"[WARNING] Syntax error parsing {file_path}: {e}")
        return violations

    for node in ast.walk(tree):
        # Check string constants
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_lower = node.value.lower()
            for forbidden in FORBIDDEN_STRINGS:
                if forbidden.lower() in val_lower:
                    violations.append((
                        file_path,
                        getattr(node, "lineno", 0),
                        forbidden,
                        f"Constant string: '{node.value}'",
                    ))
        # Check function or attribute names
        elif isinstance(node, ast.Attribute):
            attr_lower = node.attr.lower()
            for forbidden in FORBIDDEN_STRINGS:
                if forbidden.lower() in attr_lower:
                    violations.append((
                        file_path,
                        getattr(node, "lineno", 0),
                        forbidden,
                        f"Attribute call: '{node.attr}'",
                    ))
        elif isinstance(node, ast.Name):
            name_lower = node.id.lower()
            for forbidden in FORBIDDEN_STRINGS:
                if forbidden.lower() in name_lower:
                    violations.append((
                        file_path,
                        getattr(node, "lineno", 0),
                        forbidden,
                        f"Identifier name: '{node.id}'",
                    ))

    return violations


def run_audit() -> int:
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    violations: List[Tuple[str, int, str, str]] = []

    for target in TARGET_DIRS:
        target_path = os.path.join(workspace_root, target)
        if not os.path.exists(target_path):
            continue

        for root, _, files in os.walk(target_path):
            if "__pycache__" in root or ".agents" in root or "tests" in root:
                continue

            for file in sorted(files):
                if not file.endswith(".py") or file in EXCLUDED_FILES:
                    continue

                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # 1. AST Analysis
                ast_violations = check_ast_for_violations(file_path, content)
                violations.extend(ast_violations)

                # 2. Raw Line-by-Line Substring Scanner
                lines = content.splitlines()
                for line_no, line in enumerate(lines, 1):
                    line_stripped = line.strip()
                    if line_stripped.startswith("#"):
                        continue
                    line_lower = line.lower()
                    for forbidden in FORBIDDEN_STRINGS:
                        if forbidden.lower() in line_lower:
                            entry = (file_path, line_no, forbidden, line_stripped)
                            if entry not in violations:
                                violations.append(entry)

    if violations:
        print("❌ [AUDIT FAILURE] Detected forbidden destructive endpoints/mutators in production code:")
        for path, line_no, kw, snippet in violations:
            print(f"  {path}:{line_no} matches '{kw}' -> {snippet}")
        return 1

    print("✅ [AUDIT PASSED] Zero forbidden endpoints or mutating methods found in production code.")
    return 0


if __name__ == "__main__":
    sys.exit(run_audit())
