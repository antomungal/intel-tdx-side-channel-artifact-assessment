# TDXdown wolfSSL nonce-prefix reconciliation

## Background

The preserved offline audit script and the recorded wolfSSL
audit report use different effective nonce-prefix definitions.

The original script evaluates:

    (k >> (161 - 15)) == 0x7FFF

The recorded audit results are reproduced using:

    (k >> (160 - 15)) == 0x7FFF

## Verification

The corrected offline verifier processed 700,000 ECDSA
signature records from the original cryptanalysis archive.

Results:

- 700,000 observations processed.
- 14 selected observations.
- 0 invalid records.
- 14 true positives.
- 0 false positives.
- 17 false negatives.
- 699,969 true negatives.
- Precision: 1.0.
- Recall: 0.45161290322580644.
- Specificity: 1.0.
- All comparisons against the preserved audit report passed.

The archive and its two relevant input files also passed
SHA-256 integrity verification.

## Interpretation

The successful reproduction uses a fixed 160-bit nonce-prefix
predicate.

The preserved original script uses a 161-bit reference width.
Executing that predicate does not reproduce the recorded
audit metrics.

The corrected predicate is therefore an explicitly documented
reconciliation, not a byte-for-byte reproduction of the
preserved script.

The reference private key is used solely to reconstruct
nonces for offline verification.

This analysis does not demonstrate private-key recovery,
live Intel TDX exploitation, or an independent side-channel
measurement campaign.

## Reproducibility

Run from the repository root:

    python3 experiments/tdxdown/scripts/verify_wolfssl.py \
      --archive /path/to/cryptanalysis.zip \
      --reference /path/to/tdxdown_wolfssl_offline_audit.json

The original cryptanalysis archive must be obtained separately.
