#!/usr/bin/env python3
# Author: Antonio Muñoz - NICS Lab - UMA

"""Offline verification of TDXdown wolfSSL ECDSA evidence.

Requires separately obtained original cryptanalysis.zip.
Does not execute Intel TDX, recover private keys, or export key material.
"""

import argparse
import collections
import hashlib
import json
import zipfile
from itertools import zip_longest
from pathlib import Path

PREFIX = (
    "cryptanalysis/wolfssl/leakage_exploitation/"
    "ECC_SECP160R1/SEL_ECC_SECP160R1-combined-"
)

ORDER = int(
    "100000000000000000001F4C8F927AED3CA752257", 16
)

EXPECTED = {
    "archive_sha256":
        "5657c042c3d8146d0518cd0e1d8bd67f45ebd72c86ef290d08a9f226f5a006b9",
    "classification_sha256":
        "261ff2c45dde23a4216a183927e5c50288945e67f20a7f6c2896d1a1b5e4a7d8",
    "signatures_sha256":
        "a853b7a5c9fda6304b164e70b8ec09df3085384661a35d7d1c3aae0e2f76d1e2",
    "observations": 700000,
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_der_integer(data, offset):
    if offset + 2 > len(data) or data[offset] != 0x02:
        raise ValueError("Invalid DER INTEGER tag")

    length = data[offset + 1]
    start = offset + 2
    end = start + length

    if length == 0 or end > len(data):
        raise ValueError("Invalid DER INTEGER length")

    value = data[start:end]

    if value[0] & 0x80:
        raise ValueError("Negative DER INTEGER")

    if len(value) > 1 and value[0] == 0 and not (value[1] & 0x80):
        raise ValueError("Non-minimal DER INTEGER")

    return int.from_bytes(value, "big"), end


def parse_signature(line):
    data = bytes.fromhex(line.decode("ascii").strip())

    if len(data) < 8 or data[0] != 0x30:
        raise ValueError("Invalid DER SEQUENCE")

    if data[1] >= 0x80 or data[1] != len(data) - 2:
        raise ValueError("Invalid DER SEQUENCE length")

    r, offset = read_der_integer(data, 2)
    s, offset = read_der_integer(data, offset)

    if offset != len(data):
        raise ValueError("Trailing DER data")

    if not (0 < r < ORDER and 0 < s < ORDER):
        raise ValueError("ECDSA component out of range")

    return r, s


def verify(archive, reference):
    errors = []

    print("=== ORIGINAL ARCHIVE ===")

    actual_archive_hash = sha256_file(archive)
    archive_ok = actual_archive_hash == EXPECTED["archive_sha256"]
    print("Archive SHA-256:", "PASS" if archive_ok else "FAIL")

    if not archive_ok:
        errors.append("Archive SHA-256 mismatch")

    print("\n=== CRYPTOGRAPHIC RECORDS ===")

    counts = collections.Counter()
    selected_indices = []
    invalid = []
    total = 0
    class_hash = hashlib.sha256()
    sig_hash = hashlib.sha256()

    with zipfile.ZipFile(archive) as z:
        with z.open(PREFIX + "classification.txt") as classifications:
            with z.open(PREFIX + "signatures.txt") as signatures:

                header = [signatures.readline() for _ in range(3)]

                if any(not line for line in header):
                    raise ValueError("Incomplete signature header")

                # The reference private key and message value are read
                # only into memory. Neither is printed nor exported.
                d = int(header[1].strip(), 16)
                h = int(header[2].strip(), 16)

                for line in header:
                    sig_hash.update(line)

                for index, pair in enumerate(
                    zip_longest(classifications, signatures)
                ):
                    class_line, signature_line = pair

                    if class_line is None or signature_line is None:
                        errors.append(
                            "Classification/signature length mismatch"
                        )
                        break

                    total += 1
                    class_hash.update(class_line)
                    sig_hash.update(signature_line)

                    try:
                        label_text = class_line.strip()

                        if label_text not in (b"0", b"1"):
                            raise ValueError("Invalid classification label")

                        label = int(label_text)
                        r, s = parse_signature(signature_line)

                        nonce = ((h + r * d) * pow(s, -1, ORDER)) % ORDER

                        # Exact predicate used in the original audit.
                        matches = (nonce >> (160 - 15)) == 0x7FFF

                        counts[(label, matches)] += 1

                        if label:
                            selected_indices.append(index)

                    except (ValueError, UnicodeError) as exc:
                        invalid.append({
                            "index": index,
                            "error": str(exc),
                        })
                        if len(invalid) >= 10:
                            errors.append("Too many invalid records")
                            break

    print("Observations processed:", total)
    print("Selected labels:", len(selected_indices))
    print("Invalid records:", len(invalid))

    if total != EXPECTED["observations"]:
        errors.append("Unexpected observation count")

    class_ok = (
        class_hash.hexdigest() == EXPECTED["classification_sha256"]
    )
    sig_ok = (
        sig_hash.hexdigest() == EXPECTED["signatures_sha256"]
    )

    print("Classification SHA-256:", "PASS" if class_ok else "FAIL")
    print("Signatures SHA-256:", "PASS" if sig_ok else "FAIL")

    if not class_ok:
        errors.append("Classification digest mismatch")
    if not sig_ok:
        errors.append("Signature digest mismatch")
    if invalid:
        errors.append("Invalid cryptographic records")

    tp = counts[(1, True)]
    fp = counts[(1, False)]
    fn = counts[(0, True)]
    tn = counts[(0, False)]

    # These names follow the original report's convention:
    # classification=1 is the selected event;
    # matches=True is the reconstructed nonce-prefix condition.
    metrics = {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "specificity": tn / (tn + fp) if tn + fp else None,
        "selected_fraction": (
            (tp + fp) / total if total else None
        ),
        "matching_prefix_fraction": (
            (tp + fn) / total if total else None
        ),
    }

    print("\n=== RECOMPUTED METRICS ===")
    for key, value in metrics.items():
        print(f"{key}: {value}")

    if reference is not None:
        report = json.loads(reference.read_text(encoding="utf-8"))

        print("\n=== REFERENCE REPORT COMPARISON ===")

        for key, value in metrics.items():
            recorded = report.get("metrics", {}).get(key)
            if isinstance(value, float) and isinstance(recorded, (int, float)):
                ok = abs(value - recorded) < 1e-12
            else:
                ok = value == recorded

            print(f"{key}: {'PASS' if ok else 'FAIL'}")
            if not ok:
                errors.append(f"Metric mismatch: {key}")

        checks = {
            "total": total,
            "matching_prefix_all": tp + fn,
        }

        for key, value in checks.items():
            ok = report.get(key) == value
            print(f"{key}: {'PASS' if ok else 'FAIL'}")
            if not ok:
                errors.append(f"Reference mismatch: {key}")

        reference_selected = [
            item["index_zero_based"]
            for item in report.get("selected", [])
        ]

        ok = selected_indices == reference_selected
        print("Selected indices:", "PASS" if ok else "FAIL")

        if not ok:
            errors.append("Selected indices mismatch")

        recorded_comparison = report.get("prefix_comparison", {})
        actual_comparison = {
            str((label, matches)): count
            for (label, matches), count in counts.items()
        }

        ok = recorded_comparison == actual_comparison
        print("Prefix comparison:", "PASS" if ok else "FAIL")

        if not ok:
            errors.append("Prefix comparison mismatch")

    print("\n=== RESULT ===")
    print("Errors:", len(errors))

    for error in errors:
        print("ERROR:", error)

    print("PASS" if not errors else "FAIL")
    return 0 if not errors else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--reference", type=Path)

    args = parser.parse_args()

    if not args.archive.is_file():
        parser.error("Original archive not found")

    if args.reference is not None and not args.reference.is_file():
        parser.error("Reference report not found")

    return verify(args.archive, args.reference)


if __name__ == "__main__":
    raise SystemExit(main())
