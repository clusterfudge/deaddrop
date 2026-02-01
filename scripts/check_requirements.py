#!/usr/bin/env python3
"""Pre-commit hook to verify requirements.txt versions match uv.lock.

This checks that:
1. All packages in requirements.txt have matching versions in uv.lock
2. The requirements.txt includes -e . for the editable package install
"""

import re
import sys
from pathlib import Path


def parse_uv_lock(lock_path: Path) -> dict[str, str]:
    """Parse uv.lock and return a dict of package_name -> version."""
    packages = {}
    content = lock_path.read_text()

    # Parse TOML-like format - each [[package]] block has name and version
    current_name = None
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("name = "):
            # Extract name from: name = "package-name"
            match = re.match(r'name = "([^"]+)"', line)
            if match:
                current_name = match.group(1)
        elif line.startswith("version = ") and current_name:
            # Extract version from: version = "1.2.3"
            match = re.match(r'version = "([^"]+)"', line)
            if match:
                packages[current_name] = match.group(1)
                current_name = None

    return packages


def parse_requirements(req_path: Path) -> tuple[dict[str, str], bool]:
    """Parse requirements.txt and return (dict of package_name -> version, has_editable)."""
    packages = {}
    has_editable = False

    content = req_path.read_text()
    for line in content.split("\n"):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Check for editable install
        if line == "-e .":
            has_editable = True
            continue

        # Skip continuation comments (lines starting with spaces followed by #)
        if line.startswith("# via"):
            continue

        # Parse package==version format
        match = re.match(r"^([a-zA-Z0-9_-]+)==([0-9][^\s;]*)", line)
        if match:
            name = match.group(1).lower()  # Normalize to lowercase
            version = match.group(2)
            packages[name] = version

    return packages, has_editable


def main() -> int:
    project_root = Path(__file__).parent.parent
    lock_path = project_root / "uv.lock"
    req_path = project_root / "requirements.txt"

    if not lock_path.exists():
        print("ERROR: uv.lock not found")
        return 1

    if not req_path.exists():
        print("ERROR: requirements.txt not found")
        return 1

    # Parse both files
    lock_packages = parse_uv_lock(lock_path)
    req_packages, has_editable = parse_requirements(req_path)

    errors = []

    # Check that -e . is present
    if not has_editable:
        errors.append("Missing '-e .' for editable package install")

    # Check version compatibility
    for req_name, req_version in req_packages.items():
        # Normalize name (replace - with _ and lowercase)
        normalized = req_name.replace("-", "_").lower()

        # Find matching package in lock file (try both forms)
        lock_version = None
        for lock_name, version in lock_packages.items():
            lock_normalized = lock_name.replace("-", "_").lower()
            if lock_normalized == normalized or lock_name.lower() == req_name.lower():
                lock_version = version
                break

        if lock_version is None:
            # Package not in lock file - this might be OK for transitive deps
            # that were resolved differently, but let's warn
            pass  # Don't error on this, lock file might not have all transitives
        elif lock_version != req_version:
            errors.append(
                f"Version mismatch for {req_name}: "
                f"requirements.txt has {req_version}, uv.lock has {lock_version}"
            )

    if errors:
        print("ERROR: requirements.txt is out of sync with uv.lock")
        print()
        for error in errors:
            print(f"  - {error}")
        print()
        print("To fix, run:")
        print(
            "  uv pip compile pyproject.toml --extra turso -o requirements.txt "
            "&& echo '-e .' >> requirements.txt"
        )
        return 1

    print("requirements.txt is compatible with uv.lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
