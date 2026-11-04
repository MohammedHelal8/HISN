"""Conservative, read-only HISN exception preflight."""

import argparse
import re
from pathlib import Path

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.blocking_exception import BlockingException
from app.security_engine.detection import exception_matches

BASE = Path("/etc/e2guardian/lists/example.group")

SITE_FILES = [
    "exceptionsitelist",
    "localexceptionsitelist",
    "semiexceptionsitelist",
    "localsemiexceptionsitelist",
]

OTHER_FILES = [
    "exceptionurllist",
    "localexceptionurllist",
    "exceptionregexpurllist",
    "exceptionregexpuseragentlist",
]

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

INCLUDE_RE = re.compile(r"^\.Include<([^<>]+)>$")


def matches_domain(domain, entry):
    entry = entry.lower()
    return domain == entry or domain.endswith("." + entry)


def read_list(path, visited):
    path = path.resolve(strict=True)
    root = BASE.resolve(strict=True)

    if not path.is_relative_to(root):
        raise ValueError("Include outside approved list directory")

    if path in visited:
        raise ValueError("Recursive or repeated Include")

    visited.add(path)

    if not path.is_file():
        raise ValueError("Not a regular list file")

    result = []

    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        include = INCLUDE_RE.fullmatch(line)
        if include:
            child = Path(include.group(1))
            if not child.is_absolute():
                child = path.parent / child

            result.extend(read_list(child, visited))
            continue

        result.append((str(path), number, line))

    return result


def check(domain):
    reasons = []

    with SessionLocal() as db:
        exceptions = db.scalars(
            select(BlockingException)
        ).all()

        if exception_matches(domain, exceptions):
            reasons.append(
                ("BLOCKED_BY_EXCEPTION", "HISN database exception")
            )

    for name in SITE_FILES:
        try:
            lines = read_list(BASE / name, set())
        except (OSError, ValueError, UnicodeError) as exc:
            reasons.append(
                ("REVIEW_REQUIRED", f"{name}: {exc}")
            )
            continue

        for filename, number, entry in lines:
            if DOMAIN_RE.fullmatch(entry.lower()):
                if matches_domain(domain, entry):
                    reasons.append(
                        ("BLOCKED_BY_EXCEPTION",
                         f"{filename}:{number}: {entry}")
                    )
            else:
                reasons.append(
                    ("REVIEW_REQUIRED",
                     f"Unsupported site rule {filename}:{number}")
                )

    # URL and regexp exceptions may apply to this domain.
    # Until their semantics are implemented, nonempty lists
    # prevent authorization.
    for name in OTHER_FILES:
        try:
            lines = read_list(BASE / name, set())
        except (OSError, ValueError, UnicodeError) as exc:
            reasons.append(
                ("REVIEW_REQUIRED", f"{name}: {exc}")
            )
            continue

        if lines:
            reasons.append(
                ("REVIEW_REQUIRED",
                 f"{name} has {len(lines)} active entries")
            )

    return reasons


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()

    domain = args.domain.strip().lower()

    if not DOMAIN_RE.fullmatch(domain):
        parser.error("Invalid domain")

    print("=== HISN EXCEPTION PREFLIGHT ===")
    print("Target:", domain)

    try:
        findings = check(domain)
    except Exception as exc:
        print("REVIEW_REQUIRED:", exc)
        raise SystemExit(2)

    for status, reason in findings:
        print(f"{status}: {reason}")

    if findings:
        print("RESULT: NOT AUTHORIZED")
        raise SystemExit(2)

    print("RESULT: NO CONFLICT FOUND IN CHECKED SOURCES")
    print("NOTE: This is not enforcement authorization")
    print("Database changes: NONE")
    print("Policy changes: NONE")


if __name__ == "__main__":
    main()
