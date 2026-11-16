"""Fail CI on selected credential patterns and tracked environment files."""

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PATTERNS = {
    "Private key": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(
        rb"\b(?:ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{30,}"
    ),
    "AWS access key": re.compile(
        rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),
    "Google API key": re.compile(
        rb"\bAIza[A-Za-z0-9_-]{35}\b"
    ),
    "Live payment secret": re.compile(
        rb"\b(?:sk_live_|rk_live_)[A-Za-z0-9]{16,}\b"
    ),
}

SENSITIVE_EXTENSIONS = {
    ".pem", ".p12", ".pfx", ".key",
}


def git_paths(*args: str) -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", *args, "-z"],
        cwd=ROOT,
    )

    return [
        ROOT / item.decode("utf-8", errors="surrogateescape")
        for item in output.split(b"\0")
        if item
    ]


def main() -> None:
    tracked = git_paths("--cached")
    candidates = git_paths(
        "--cached",
        "--others",
        "--exclude-standard",
    )

    findings = set()
    scanned = 0

    for path in tracked:
        name = path.name.lower()

        if name == ".env" or (
            name.startswith(".env.")
            and not name.endswith(
                (".example", ".sample", ".template")
            )
        ):
            findings.add(
                (str(path.relative_to(ROOT)), "Tracked environment file")
            )

    for path in candidates:
        if not path.is_file():
            continue

        relative = str(path.relative_to(ROOT))
        name = path.name.lower()

        if path.suffix.lower() in SENSITIVE_EXTENSIONS:
            findings.add((relative, "Sensitive file extension"))

        if path.stat().st_size > 1024 * 1024:
            continue

        content = path.read_bytes()

        if b"\0" in content:
            continue

        scanned += 1

        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                findings.add((relative, label))

    print(f"Scanned {scanned} repository files")

    if findings:
        for filename, label in sorted(findings):
            print(f"REVIEW: {filename} - {label}")

        raise SystemExit(
            "Potential credential exposure detected. "
            "Review files locally; do not paste secret values."
        )

    print("PASS: Selected credential checks")
    print("NOTE: This does not replace comprehensive secret scanning.")


if __name__ == "__main__":
    main()
