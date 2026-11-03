# Reproducibility Assessment

## Scope

This artifact assesses three Intel TDX side-channel case studies:
TDXdown, TDXploit, and T-Time.

The assessment combines integrity verification, provenance checks,
offline analysis, and functional replay.

It does not reproduce the original attacks on Intel TDX hardware.

## TDXdown

The original and annotated traces were reprocessed using the
preserved trace validator.

The recomputed report matched the reference results:

- 4,237,526 paired address entries.
- Zero address mismatches.
- 85 distinct marked pages.
- 129,315 page transitions.
- 15 sequential invocation markers.

The offline wolfSSL assessment processed 700,000 signature records
without invalid records.

Its recorded confusion matrix was reproduced:

- TP: 14
- FP: 0
- FN: 17
- TN: 699,969

Reproduction requires a fixed 160-bit nonce-prefix predicate.
The preserved script instead uses a 161-bit reference width.

See `experiments/tdxdown/PREFIX_RECONCILIATION.md`.

Nonce reconstruction uses a reference private key and does not
constitute private-key recovery.

## TDXploit

The assessed TDXploit evidence package passed the recorded
integrity and traceability checks.

Verification against original sources established:

- 18 original signature files verified.
- 41 selected events.
- 38 available, structurally valid DER signatures.
- 3 confirmed missing signatures.
- Zero reported verification errors.

The assessment does not establish mathematical ECDSA signature
validity or successful private-key recovery.

The exploratory seven-bit prefix is not a confirmed TDXploit
leakage mechanism.

## T-Time

The offline functional replay verified:

- 2,501 saved traces.
- 7,503 decoder outputs.
- Zero reported replay failures.

The original decoder files were checked against their recorded
upstream SHA-256 digests.

The replay uses synthetic inputs and does not reproduce an attack
on live Intel TDX hardware.

An additional isolated offline replay was assessed on 4 November 2026,
using Python 3.14.6 and cryptography 50.0.2. Its 125-byte JSON report
was byte-identical to the preserved historical report, with SHA-256:

`7f2f4aae1be667dc14269de2c8fd896d69a772ba862ff8064051680e5a7493e7`

The additional report is preserved as
`reports/ttime-v4.1-independent-replay-2026-11-04.json`.

The comparison establishes report consistency. The isolated replay
used the same original decoders and retained synthetic traces; it
does not constitute independent algorithmic validation or hardware
attack reproduction. An independent record of the process exit status
was not retained.

The original decoder scripts match the identified upstream revision,
but their redistribution rights have not been established. The
historical manifest's decoder-hash field does not independently
establish which external scripts were executed.

## Reproducibility boundaries

The repository is currently private and contains verification
scripts, selected evidence, reports, and integrity manifests.
It also retains T-Time synthetic traces containing RSA
private-exponent bits. Public release requires a separate
review of the distributed files and Git history.

Some original inputs are not redistributed because of their size,
third-party provenance, or the presence of reference key material.

Verification against those inputs requires separately obtained
original artifacts.

The verification matrix in `reports/verification-matrix.csv`
identifies the evidence and limitations of each assessment.
