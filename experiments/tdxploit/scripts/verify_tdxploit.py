#!/usr/bin/env python3
# Author: Antonio Muñoz - NICS Lab - UMA
"""Independent integrity and traceability checks for TDXploit artifacts."""

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_der(data):
    if len(data) < 8 or data[0] != 0x30:
        raise ValueError("Invalid DER sequence")
    if data[1] & 0x80 or data[1] != len(data) - 2:
        raise ValueError("Invalid or noncanonical sequence length")

    pos = 2
    values = []

    for _ in range(2):
        if pos + 2 > len(data) or data[pos] != 0x02:
            raise ValueError("Missing DER INTEGER")

        size = data[pos + 1]
        pos += 2

        if size == 0 or pos + size > len(data):
            raise ValueError("Invalid INTEGER length")

        raw = data[pos:pos + size]
        pos += size

        if raw[0] & 0x80:
            raise ValueError("Negative INTEGER")
        if len(raw) > 1 and raw[0] == 0 and not (raw[1] & 0x80):
            raise ValueError("Nonminimal INTEGER")

        value = int.from_bytes(raw, "big")
        if value <= 0:
            raise ValueError("Nonpositive INTEGER")

        values.append(value)

    if pos != len(data):
        raise ValueError("Trailing DER data")

    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--original",
        type=Path,
        help="Path to the original TDXploit-main directory",
    )
    args = parser.parse_args()

    errors = []

    def check(condition, message):
        if not condition:
            errors.append(message)

    manifest = load_csv(BASE / "MANIFEST.csv")

    print("=== PACKAGE INTEGRITY ===")

    for entry in manifest:
        relative = Path(entry["path"])

        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"Unsafe manifest path: {relative}")
            continue

        path = BASE / relative

        if not path.is_file():
            errors.append(f"Missing package file: {relative}")
            continue

        raw = path.read_bytes()

        check(
            len(raw) == int(entry["bytes"]),
            f"Size mismatch: {relative}",
        )
        check(
            digest(raw) == entry["sha256"],
            f"SHA-256 mismatch: {relative}",
        )

    print("Manifest entries:", len(manifest))

    selected = load_csv(BASE / "data/selected_events.csv")
    validated = load_csv(BASE / "reports/signature_validation.csv")
    provenance = load_json(BASE / "reports/signature_provenance.json")
    summary = load_json(BASE / "reports/signature_validation_summary.json")
    selection_summary = load_json(BASE / "reports/selection_summary.json")

    def event_key(row):
        return int(row["run"]), int(row["index_0based"])

    selected_by_key = {}
    validated_by_key = {}

    for row in selected:
        key = event_key(row)
        check(key not in selected_by_key, f"Duplicate selected event: {key}")
        selected_by_key[key] = row
        check(
            int(row["iteration_1based"]) == key[1] + 1,
            f"Invalid iteration: {key}",
        )

    for row in validated:
        key = event_key(row)
        check(key not in validated_by_key, f"Duplicate validation: {key}")
        validated_by_key[key] = row

    check(
        set(selected_by_key) == set(validated_by_key),
        "Selected/validated event sets differ",
    )

    present = 0
    missing = 0
    counts_by_step = Counter()
    der_lengths = Counter()
    signature_hashes = set()

    for key, row in validated_by_key.items():
        counts_by_step[str(int(row["step_count"]))] += 1

        selected_row = selected_by_key.get(key)
        if selected_row:
            check(
                row["step_count"] == selected_row["step_count"],
                f"Step mismatch: {key}",
            )
            check(
                row["iteration_1based"]
                == selected_row["iteration_1based"],
                f"Iteration mismatch: {key}",
            )

        if row["signature_status"] == "hex_present":
            present += 1
            check(
                row["der_status"] == "valid",
                f"Invalid DER status: {key}",
            )
            der_lengths[str(int(row["der_bytes"]))] += 1
            signature_hashes.add(row["signature_sha256"])
        elif row["signature_status"] == "missing":
            missing += 1
            check(
                row["der_status"] == "not_available",
                f"Unexpected missing-signature DER status: {key}",
            )
        else:
            errors.append(f"Unknown signature status: {key}")

    check(len(selected) == int(summary["total_selected"]),
          "Selected event total mismatch")
    check(len(validated) == int(summary["total_selected"]),
          "Validation total mismatch")
    check(present == int(summary["present"]), "Present total mismatch")
    check(missing == int(summary["missing"]), "Missing total mismatch")
    check(present == int(summary["der_valid"]), "DER valid total mismatch")
    check(int(summary["der_invalid"]) == 0, "DER invalid count is nonzero")
    check(dict(counts_by_step) == {
        str(k): int(v) for k, v in summary["counts_by_step"].items()
    }, "Step distribution mismatch")
    check(dict(der_lengths) == {
        str(k): int(v)
        for k, v in summary["der_length_distribution"].items()
    }, "DER length distribution mismatch")
    check(len(signature_hashes) == int(summary["unique_signature_digests"]),
          "Unique signature digest count mismatch")
    check(len(selected) == int(selection_summary["selected_42_44"]),
          "Selection summary mismatch")

    print("\n=== EVENT TRACEABILITY ===")
    print("Selected events:", len(selected))
    print("Available signatures:", present)
    print("Missing signatures:", missing)
    print("Provenance records:", len(provenance))

    if args.original:
        print("\n=== ORIGINAL SOURCE VERIFICATION ===")

        root = (
            args.original
            / "Section3" / "openssl" / "traces"
        )

        source_cache = {}
        verified_runs = set()
        verified_signatures = 0
        verified_missing = 0

        for key, row in validated_by_key.items():
            run, index = key
            run_id = f"{run:02d}"

            if run_id not in provenance:
                errors.append(f"Missing provenance: {run_id}")
                continue

            if run_id not in source_cache:
                path = (
                    root / f"sigs-run-{run_id}"
                    / "attack-results-0_10000_signatures.csv"
                )

                if not path.is_file():
                    errors.append(f"Missing original source: {path}")
                    continue

                raw = path.read_bytes()
                record = provenance[run_id]

                if digest(raw) != record["sha256"]:
                    errors.append(f"Original SHA-256 mismatch: {run_id}")
                    continue

                if len(raw) != int(record["bytes"]):
                    errors.append(f"Original size mismatch: {run_id}")
                    continue

                lines = raw.decode("utf-8-sig").splitlines()

                if len(lines) != int(record["rows"]):
                    errors.append(f"Original row count mismatch: {run_id}")
                    continue

                source_cache[run_id] = lines
                verified_runs.add(run_id)

            if run_id not in source_cache:
                continue

            lines = source_cache[run_id]

            if not 0 <= index < len(lines):
                errors.append(f"Original index out of range: {key}")
                continue

            value = lines[index].strip()

            if row["signature_status"] == "missing":
                if value != "0x":
                    errors.append(f"Expected absent signature: {key}")
                else:
                    verified_missing += 1
                continue

            if not value.startswith("0x"):
                errors.append(f"Missing hex prefix: {key}")
                continue

            try:
                signature = bytes.fromhex(value[2:])
                r, s = parse_der(signature)
            except ValueError as exc:
                errors.append(f"DER error {key}: {exc}")
                continue

            checks = {
                "signature_sha256": digest(signature),
                "der_bytes": str(len(signature)),
                "r_bits": str(r.bit_length()),
                "s_bits": str(s.bit_length()),
                "source_sha256": provenance[run_id]["sha256"],
                "der_status": "valid",
            }

            for field, actual in checks.items():
                if row[field] != actual:
                    errors.append(f"{field} mismatch: {key}")

            verified_signatures += 1

        check(
            len(verified_runs) == len(provenance),
            "Not all original provenance records verified",
        )
        check(
            verified_signatures == present,
            "Not all available signatures verified",
        )
        check(
            verified_missing == missing,
            "Not all absent signatures confirmed",
        )

        print("Original files verified:", len(verified_runs))
        print("Signatures parsed:", verified_signatures)
        print("Missing signatures confirmed:", verified_missing)

    print("\n=== RESULT ===")
    print("Errors:", len(errors))

    for error in errors[:30]:
        print("ERROR:", error)

    print("PASS" if not errors else "FAIL")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
