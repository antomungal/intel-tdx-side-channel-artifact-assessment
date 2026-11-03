# TDXploit: Offline Evidence Assessment

## Scope

This directory contains an offline assessment of experimental
artifacts associated with TDXploit.

The assessment focuses on the integrity, provenance, and traceability
of recorded observations and selected ECDSA signatures.

It does not reproduce an attack on Intel TDX hardware.

## Experimental evidence

The analyzed campaign contains 260,000 recorded observations
across 26 runs.

The selection criterion identifies 41 observations with step
counts of 42 or 44.

Of these observations:

- 38 have an available signature.
- 3 have no available signature.
- The 38 available signatures have structurally valid DER encodings.
- The 3 missing signatures are confirmed against their original
  source records.

The original signature files associated with the selected events
are represented by 18 SHA-256 provenance records.

## Verification

The verification script supports two modes.

### Package verification

Run from the repository root:

    python3 experiments/tdxploit/scripts/verify_tdxploit.py

This checks the integrity of the packaged evidence and consistency
between selected events, signature validation records, and summaries.

### Verification against original sources

Obtain the original TDXploit source tree separately and run:

    python3 experiments/tdxploit/scripts/verify_tdxploit.py \
      --original /path/to/TDXploit-main

This additionally checks:

- SHA-256 digests of original signature files.
- Original source file sizes and row counts.
- Selected observation indices.
- Signature availability.
- DER encoding and ECDSA integer components.
- Individual signature digests.

Both verification modes passed locally with zero reported errors
on November 1, 2026.

## Interpretation and limitations

The seven-bit prefix 1101011 is evaluated as an exploratory
hypothesis originating from the TDXdown analysis.

It is not established as a validated TDXploit leakage mechanism.

The nonce-related analysis uses a reference private key to compute
nonce values. It must not be interpreted as private-key recovery.

The available verification establishes structural and provenance
properties of recorded signatures. It does not establish their
mathematical ECDSA validity against the corresponding messages
and public keys.

The full 260,000-observation dataset and original signature files
are not included in this package. Consequently, package-only
verification does not independently reconstruct every reported
aggregate or reproduce the original experimental campaign.

The original-source verification mode requires separately obtained
third-party source data.

## Files

- `MANIFEST.csv`: SHA-256 inventory of packaged evidence.
- `data/`: aggregate statistics and selected-event records.
- `reports/`: experimental summaries, provenance, and validation.
- `scripts/verify_tdxploit.py`: independent verification procedure.

## Reproducibility boundary

This artifact supports offline integrity and traceability checks.
It does not establish live Intel TDX exploitability, end-to-end
private-key recovery, or reproduction of the original hardware attack.
