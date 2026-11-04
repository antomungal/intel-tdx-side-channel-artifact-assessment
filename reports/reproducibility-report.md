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

## Additional cryptographic verification

### TDXD-04: wolfSSL/secp160r1

The archived recovery log reports two private-key candidates from a lattice-based procedure using 12 samples. An independent offline comparison against the reference key stored in the original signature dataset established that the first candidate matches the 160-bit reference key; the second does not. The lattice procedure and the original Intel TDX execution were not repeated.

The original `key_recovery.py` also contains an intermediate-output defect: the second JSON write reuses the first output filename, overwriting the previously written sample data. The original third-party code has not been modified. The effect on preservation of intermediate files is documented separately from the historical recovery result.

### TDXD-05: OpenSSL/brainpoolP224r1

The original input contains a reference private key, a reference message and 33 signature records. The historical recovery log reports a recovered private key. An independent offline comparison confirmed that the recovered value equals the reference key. The original cryptanalytic solver and Intel TDX acquisition were not rerun.

### TDXP-03: ECDSA signature verification

An independent verification using OpenSSL 3.6.3, ECDSA over brainpoolP224r1 and SHA-224 accepted all 38 available signatures among 41 selected events. Three events lacked signatures; no available signature failed verification. The machine-readable report is `reports/tdxploit-ecdsa-verification.json`.

The reference public key was derived from a known experimental private key. This verifies the mathematical validity of the archived signatures but does not independently demonstrate nonce leakage, private-key recovery or execution of TDXploit on Intel TDX hardware.

### Evidence boundary

The TDXdown key-recovery logs and original cryptographic datasets remain outside this repository. Their results have been checked locally but are not yet independently reproducible from the packaged artifact alone. The TDXploit verification report is packaged, while its original input CSV remains external. These distinctions must be retained in any public reproducibility claim.

## T-Time v4.1 — verified fresh replay and decoder provenance

A new functional replay was executed on a separate working copy of the retained v4.1 inputs, using the two unmodified T-Time decoder scripts from upstream commit `a0db080725e79339bcacbefd8fea4b6abdfcd352`. The scripts were verified against SHA-256 `01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223` (`pattern_second.py`) and `98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4` (`pattern_third.py`), matching the v4.1 campaign copies.

The replay processed **2,501 retained synthetic traces**, checked **7,503 method outputs**, reported **zero failures**, returned `all_matched: true`, and exited with status **0**. The retained inputs were reused; neither the RSA key nor the observations were regenerated. The replay script wrote its report into a temporary working copy, leaving the published inputs unchanged.

The original scripts are third-party dependencies and are not tracked in the assessment repository. A clean checkout therefore requires obtaining the scripts separately from the pinned upstream revision, checking their SHA-256 digests, and placing them under `experiments/ttime/v4.1/original/`. The v4.1 README documents this procedure.

The T-Time v4.1 reconstruction results are repeatable using the retained synthetic inputs and the original, hash-verified upstream decoders. This does not establish independent decoder correctness or reproduce side-channel acquisition on Intel TDX hardware. The retained `reference_bits` may expose the private exponent of the throwaway experimental RSA key and must be treated as disclosed experimental data. The replay does not independently establish the cryptographic validity of a reconstructed exponent.
