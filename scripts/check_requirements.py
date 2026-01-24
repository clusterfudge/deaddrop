#!/usr/bin/env python3
"""Pre-commit hook to verify requirements.txt has the same packages as uv pip compile output.

Note: This check compares package names only, not exact versions, since version
resolution can differ between environments (different uv versions, Python versions,
or package index states).
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path


def extract_packages(content: str) -> set[str]:
    """Extract package names from requirements.txt content.

    Returns a set of lowercase package names, ignoring versions and markers.
    """
    packages = set()
    for line in content.strip().split("\n"):
        # Skip comments
        if line.strip().startswith("#"):
            continue
        # Skip empty lines
        if not line.strip():
            continue
        # Skip via comments (indented)
        if line.startswith("    "):
            continue
        # Skip -e . (editable install)
        if line.strip() == "-e .":
            continue
        # Extract just the package name (before ==, >=, ;, etc.)
        match = re.match(r"^([a-zA-Z0-9_-]+)", line.strip())
        if match:
            packages.add(match.group(1).lower().replace("-", "_"))
    return packages


def main() -> int:
    # Get the project root (where pyproject.toml is)
    project_root = Path(__file__).parent.parent
    requirements_path = project_root / "requirements.txt"

    if not requirements_path.exists():
        print("ERROR: requirements.txt not found")
        return 1

    # Read current requirements.txt
    current_requirements = requirements_path.read_text()

    # Generate expected requirements with uv
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        temp_path = f.name

    try:
        result = subprocess.run(
            [
                "uv",
                "pip",
                "compile",
                "pyproject.toml",
                "--extra",
                "turso",
                "--universal",
                "-o",
                temp_path,
            ],
            capture_output=True,
            text=True,
            cwd=project_root,
        )

        if result.returncode != 0:
            print(f"ERROR: uv pip compile failed:\n{result.stderr}")
            return 1

        # Read generated requirements
        generated = Path(temp_path).read_text()

        # Compare package sets (ignoring versions)
        current_packages = extract_packages(current_requirements)
        expected_packages = extract_packages(generated)

        missing = expected_packages - current_packages
        extra = current_packages - expected_packages

        if missing or extra:
            print("ERROR: requirements.txt packages don't match pyproject.toml")
            print("\nTo fix, run:")
            print(
                "  uv pip compile pyproject.toml --extra turso --universal -o requirements.txt && echo '-e .' >> requirements.txt"
            )

            if missing:
                print("\nMissing packages:")
                for pkg in sorted(missing):
                    print(f"  + {pkg}")

            if extra:
                print("\nExtra packages:")
                for pkg in sorted(extra):
                    print(f"  - {pkg}")

            return 1

        print("requirements.txt packages match pyproject.toml")
        return 0

    finally:
        Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
