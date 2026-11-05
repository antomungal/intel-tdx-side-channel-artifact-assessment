
# Author: Antonio Muñoz - NICS Lab - UMA
"""Audit tracked files and optionally rebuild the root integrity manifest."""

import argparse
import csv
import hashlib
import io
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "MANIFEST.csv"


def tracked_files():
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = [
        Path(p.decode("utf-8"))
        for p in result.stdout.split(b"\0")
        if p
    ]
    return sorted(
        p for p in paths
        if p.as_posix() != "MANIFEST.csv"
    )


def file_record(path):
    full = ROOT / path
    data = full.read_bytes()
    return {
        "path": path.as_posix(),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def read_manifest():
    if not MANIFEST.exists():
        return {}

    with MANIFEST.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    return {row["path"]: row for row in rows}


def build_manifest(records):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=["path", "size_bytes", "sha256"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="Update MANIFEST.csv after reviewing the audit",
    )
    args = parser.parse_args()

    paths = tracked_files()
    missing_files = [p for p in paths if not (ROOT / p).is_file()]

    if missing_files:
        print("ERROR: tracked files missing from working tree")
        for path in missing_files:
            print(" ", path)
        raise SystemExit(2)

    records = [file_record(p) for p in paths]
    current = read_manifest()
    expected = {r["path"]: r for r in records}

    missing = sorted(set(expected) - set(current))
    extra = sorted(set(current) - set(expected))

    changed = sorted(
        path
        for path in set(expected) & set(current)
        if (
            str(expected[path]["size_bytes"])
            != str(current[path]["size_bytes"])
            or expected[path]["sha256"] != current[path]["sha256"]
        )
    )

    print("=== RELEASE MANIFEST AUDIT ===")
    print("Tracked files excluding MANIFEST.csv:", len(paths))
    print("Missing manifest entries:", len(missing))
    print("Obsolete manifest entries:", len(extra))
    print("Changed entries:", len(changed))

    for title, entries in (
        ("MISSING", missing),
        ("OBSOLETE", extra),
        ("CHANGED", changed),
    ):
        for path in entries:
            print(f"{title}: {path}")

    if args.write:
        MANIFEST.write_text(
            build_manifest(records),
            encoding="utf-8",
        )
        print("MANIFEST.csv updated.")
    elif missing or extra or changed:
        print("AUDIT: differences found; no files modified.")
    else:
        print("AUDIT: PASS")


if __name__ == "__main__":
    main()
