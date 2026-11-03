# Reproducibility and verification guide

Author: Antonio Muñoz - NICS Lab - UMA

## Scope and interpretation

This artifact assesses three published Intel TDX side-channel case studies through independently checked source provenance, recorded evidence, offline processing, and synthetic experiments. **It does not reproduce the attacks on live Intel TDX hardware.** The three verification levels are different and must not be conflated:

- **TDXdown:** offline verification of the original wolfSSL ECDSA records and a separately performed replay of recorded page traces.
- **TDXploit:** integrity and source-level traceability checks on selected events and DER-encoded signatures.
- **T-Time:** replay of original third-party decoders on **synthetically generated** RSA-derived observations, not on traces acquired from an RSA execution under TDX.

A successful verifier run supports only the claims explicitly tested by that verifier. Original third-party inputs are obtained separately and are not redistributed here.

## Environment

The offline TDXdown and TDXploit verifiers use the Python standard library. T-Time generation additionally requires `cryptography`. The environment previously checked for this assessment used Python 3.14.6 and `cryptography==50.0.2`; these versions describe a checked environment, not a proven minimum compatibility requirement.

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install 'cryptography==50.0.2'
.venv/bin/python -c 'import cryptography; print(cryptography.__version__)'
```

Do not add `.venv`, original third-party archives, private keys, or sensitive T-Time traces to Git. All commands below assume the current directory is the repository root. Paths to externally acquired inputs must be supplied by the reviewer.

## TDXdown: wolfSSL evidence

Obtain the original `cryptanalysis.zip` from the upstream TDXdown publication/artifact, and consult `THIRD_PARTY_SOURCES.md` for its provenance. This archive **contains reference private-key material**: keep it private and do not publish it in this repository.

```bash
.venv/bin/python experiments/tdxdown/scripts/verify_wolfssl.py \
  --archive '/absolute/path/to/cryptanalysis.zip'
```

Optionally compare the computed statistics to the preserved reference report, using the exact file identified in the repository's TDXdown documentation:

```bash
.venv/bin/python experiments/tdxdown/scripts/verify_wolfssl.py \
  --archive '/absolute/path/to/cryptanalysis.zip' \
  --reference '/absolute/path/to/reference-report.json'
```

**Acceptance:** exit status zero and final `PASS`; archive and constituent hashes must match; 700,000 observations must be processed without invalid records; with `--reference`, all recorded statistics and selected indices must match. The verifier uses the reference private key to reconstruct ECDSA nonces for classification; this is **not** private-key recovery. The original-versus-corrected nonce-prefix interpretation is documented in `experiments/tdxdown/PREFIX_RECONCILIATION.md` and must not be silently conflated.

The separate page-trace replay previously checked 4,237,526 paired addresses, zero address mismatches, and 15 marked invocations. It used a separate original trace validator and external original archive. That replay is documented in the preserved reports; the command above does **not** reproduce that page-trace validation.

## TDXploit: selected-event traceability

For internal package consistency checks:

```bash
.venv/bin/python experiments/tdxploit/scripts/verify_tdxploit.py
```

For source-level checks, separately obtain the original TDXploit repository and pass the root containing `Section3/openssl/traces`:

```bash
.venv/bin/python experiments/tdxploit/scripts/verify_tdxploit.py \
  --original '/absolute/path/to/TDXploit-main'
```

**Acceptance:** exit status zero, final `PASS`, and zero reported errors. The previously verified dataset contained 41 selected events, 38 available structurally valid DER signatures, and three confirmed missing signatures. The verifier checks SHA-256 provenance, row selection, DER structure, and consistency with recorded summaries. It does **not** perform ECDSA signature verification, recover a private key, or execute TDXploit on TDX hardware.

## T-Time v4.1: decoder provenance and replay

The generator and replay scripts are:

- `experiments/ttime/v4.1/run_v4.py`
- `experiments/ttime/v4.1/replay_v4_1.py`

The generator requires **unchanged** upstream `pattern_second.py` and `pattern_third.py` from the T-Time `attack/T-Time_poc_host/poc/evaluation_mbedtls/parse/restore/` directory. See `THIRD_PARTY_SOURCES.md` for the upstream revision. Expected SHA-256 values:

| Upstream decoder | SHA-256 |
|---|---|
| `pattern_second.py` | `01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223` |
| `pattern_third.py` | `98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4` |

Configure the directory containing **these two files**, rather than the `threshold/restore` variant:

```bash
export TTIME_ORIGINAL_DIR='/absolute/path/to/parse/restore'
shasum -a 256 "$TTIME_ORIGINAL_DIR/pattern_second.py" \
  "$TTIME_ORIGINAL_DIR/pattern_third.py"
```

`run_v4.py` verifies both hashes before executing either decoder. It accepts `--seed`, `--repeats`, `--window`, `--full-baseline`, `--output`, and `--retain-traces`. **Do not run it with `--output` pointing to the preserved `results_100` directory:** it writes `trials.csv`, `summary.csv`, `manifest.json`, `baseline_replay.json`, and optionally `trace_replay.jsonl` there.

The existing v4.1 evidence was generated with 100 repetitions per condition, a 64-bit window, a single full-exponent baseline, and retained traces. The expected record counts are 7,503 method outputs, 2,501 retained trace records, and 78 summary rows. Key generation is nondeterministic; the seed controls selection and perturbation only. Regeneration is therefore **not expected to produce byte-identical outputs**.

### Replay existing retained evidence without changing the repository

The preserved `results_100/trace_replay.jsonl` contains original private-exponent bitstrings from an experimental key and **must be treated as sensitive**. The following copies the existing results into a private temporary directory, replays the original decoders there, and removes the copy on exit. Run it only on a trusted local machine with the decoder directory already configured.

```bash
set -e
umask 077
REPLAY_TMP="$(mktemp -d)"
trap 'rm -rf -- "$REPLAY_TMP"' EXIT
cp -R experiments/ttime/v4.1/results_100 "$REPLAY_TMP/results_100"
.venv/bin/python experiments/ttime/v4.1/replay_v4_1.py \
  --output "$REPLAY_TMP/results_100"
```

**Acceptance:** the replay report must state `trace_count: 2501`, `method_outputs_checked: 7503`, `expected_rows: 7503`, an empty `failures` list, and `all_matched: true`; the process must exit with status zero. This checks decoder outputs and saved trial records, **not** real-world attack feasibility. The script writes `replay_report.json` into the supplied output directory, hence the temporary copy.

### Known provenance-reporting limitation

When `TTIME_ORIGINAL_DIR` is set, `run_v4.py` executes decoders from that external directory, but the generated manifest's `original_script_sha256` field currently enumerates Python files under the local `experiments/ttime/v4.1/original/` directory. That field can therefore be empty or fail to describe the **executed** decoders. For provenance, rely on the generator's enforced upstream SHA-256 checks, the hashes above, and the independently verified upstream revision; **do not interpret the manifest field alone as proof of which decoder files ran**. Historical manifests are preserved unchanged. This reporting limitation should be corrected before any *new* experimental campaign, but does not require regenerating existing evidence.

### Scientific limits

The two label-oracle methods use generator-provided event labels and are not deployable attacks. The synthetic event encoding is not derived from measured RSA execution. Signature verification and the modular RSA check in the generator use the **original** private key. An exact match of the reconstructed exponent is the full-baseline comparison; the artifact does not separately demonstrate a cryptographic operation using the reconstructed exponent. No live TDX acquisition is performed.

## Evidence integrity and publication boundaries

- Review `MANIFEST.csv`, the case-specific manifests, `reports/verification-matrix.csv`, and `reports/reproducibility-report.md` alongside this guide.
- Check SHA-256 and byte sizes against the manifests; a clean Git working tree alone does not prove artifact integrity.
- Do not redistribute third-party code or datasets without verifying their licenses and terms.
- Do not commit `cryptanalysis.zip`, private-key material, or T-Time retained trace files containing RSA exponent bits.
- Reproducibility of offline processing must not be described as reproduction of an attack on Intel TDX hardware.

This guide documents the verified interfaces and the already observed checks. It does not claim that its commands were re-executed in a new clean clone after this document was written.
