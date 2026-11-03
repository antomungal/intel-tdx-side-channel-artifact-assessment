# Intel TDX Side-Channel Artifact Assessment

Reproducibility and verification artifacts accompanying the manuscript
*Execution Observability and Residual Side-Channel Surfaces in Intel TDX*.

## Scope

This repository contains offline verification procedures, selected
experimental evidence, integrity manifests, and reproducibility reports
for three Intel TDX side-channel case studies:

- TDXdown
- TDXploit
- T-Time

The objective is to assess the integrity, traceability, and offline
reproducibility of the available experimental evidence.

This repository does not reproduce the original attacks on live
Intel TDX hardware.

## Repository structure

- `experiments/tdxdown/`: trace verification and offline wolfSSL
  ECDSA nonce-prefix analysis.
- `experiments/tdxploit/`: selected-event consistency, signature
  provenance, and integrity verification.
- `experiments/ttime/v4.1/`: synthetic-trace replay and RSA-related
  experimental results.
- `reports/verification-matrix.csv`: verification claims, evidence,
  results, and limitations.
- `reports/reproducibility-report.md`: consolidated assessment.
- `THIRD_PARTY_SOURCES.md`: external source provenance and licensing
  status.

## Verification summary

### TDXdown

The offline trace analysis processed 4,237,526 paired address entries
without mismatches.

The wolfSSL assessment processed 700,000 signature observations and
reproduced the recorded confusion matrix:

- TP: 14
- FP: 0
- FN: 17
- TN: 699,969

The preserved audit script and recorded report differ in their
nonce-prefix width convention.

See `experiments/tdxdown/PREFIX_RECONCILIATION.md`.

Nonce reconstruction uses reference cryptographic material and
does not demonstrate private-key recovery.

### TDXploit

The integrity and provenance assessment verified:

- 18 original source files.
- 41 selected events.
- 38 structurally valid DER signatures.
- 3 confirmed missing signatures.

The assessment does not demonstrate mathematical signature validity
or successful private-key recovery.

### T-Time

The offline assessment includes:

- 2,501 retained synthetic traces.
- 7,503 decoder outputs.
- Zero reported replay failures.

The retained trace file matches its recorded SHA-256 digest.

The original decoder scripts are external dependencies and are not
included in this repository.

## Reproducibility boundaries

Some verification procedures require original datasets, source
artifacts, or reference cryptographic material that is not
redistributed here.

The public package supports integrity checks and inspection of
retained evidence. Full reproduction of all offline assessments
requires separately obtained inputs.

No claim is made that these procedures independently reproduce
side-channel acquisition on Intel TDX hardware.

## Documentation

See:

- `reports/verification-matrix.csv`
- `reports/reproducibility-report.md`
- `THIRD_PARTY_SOURCES.md`
- Experiment-specific README files.

## Citation

Citation information will be added following manuscript publication.

## License

Licensing and third-party redistribution conditions are under review.
No repository-wide license is granted at this stage.
