# T-Time v4.1 — auditable synthetic RSA-derived reconstruction

Author: Antonio Muñoz - NICS Lab - UMA

## Scientific scope

This campaign evaluates the original T-Time reconstruction routines on synthetic observations derived from a valid RSA-2048 private exponent. These are not execution-derived timing measurements from an Intel TDX trust domain, nor evidence of a reproduced hardware RSA attack. The original third-party decoders are not modified.

## Recorded campaign

The campaign consists of 25 perturbation conditions with 100 repetitions each (64-bit windows), plus one full-length baseline. It retains 2,501 input traces (2,500 windows and one baseline), 7,503 trial-method outputs across three methods, and 78 summary rows. The full baseline is one trace, not 100 repetitions. The two label-oracle methods use privileged generator labels and are not deployable attacks.

## Upstream decoder dependencies

The assessment repository does not redistribute the original T-Time scripts. Obtain the following unmodified files from https://github.com/koreacsl/T-Time at commit:

`a0db080725e79339bcacbefd8fea4b6abdfcd352`

Upstream directory: `attack/T-Time_poc_host/poc/evaluation_mbedtls/parse/restore/`

- `pattern_second.py`: SHA-256 `01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223`
- `pattern_third.py`: SHA-256 `98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4`

Place the two files in `experiments/ttime/v4.1/original/`. The files are third-party code and must retain their original contents and attribution. The listed SHA-256 values were verified against both the pinned upstream commit and the v4.1 campaign copies.

### Retrieve and verify the original decoders

Run the following commands from `experiments/ttime/v4.1/`. This fetches the pinned upstream revision separately and checks the decoder files before use. Do not add the upstream scripts to the assessment repository without establishing redistribution permissions.

```bash
# Author: Antonio Muñoz - NICS Lab - UMA
(
(
set -e

COMMIT='a0db080725e79339bcacbefd8fea4b6abdfcd352'
SOURCE='attack/T-Time_poc_host/poc/evaluation_mbedtls/parse/restore'

UPSTREAM_DIR="$(mktemp -d "${TMPDIR:-/tmp/}ttime-upstream-XXXXXX")"
trap 'rm -rf "$UPSTREAM_DIR"' EXIT

git clone --quiet https://github.com/koreacsl/T-Time.git "$UPSTREAM_DIR/T-Time"
git -C "$UPSTREAM_DIR/T-Time" cat-file -e "$COMMIT^{commit}"

mkdir -p original

for NAME in pattern_second.py pattern_third.py; do
    git -C "$UPSTREAM_DIR/T-Time" show "$COMMIT:$SOURCE/$NAME" > "$UPSTREAM_DIR/$NAME"
done

printf '%s  %s\\n' \\
    '01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223' \\
    "$UPSTREAM_DIR/pattern_second.py" \\
    '98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4' \\
    "$UPSTREAM_DIR/pattern_third.py" | shasum -a 256 -c

for NAME in pattern_second.py pattern_third.py; do
    if [ -e "original/$NAME" ]; then
        cmp "original/$NAME" "$UPSTREAM_DIR/$NAME" || {
            echo "ERROR: Existing decoder differs: $NAME" >&2
            exit 1
        }
    else
        cp "$UPSTREAM_DIR/$NAME" "original/$NAME"
    fi
done

echo "PASS: Original T-Time decoders verified."
)
)
```

The clone step may be large because the upstream repository contains additional components. An existing verified local clone of the pinned upstream revision may be used instead. Do not execute the replay if either hash differs.

## Replay retained results (do not regenerate the campaign)

Install the required Python dependency in an isolated environment (`cryptography`). To avoid overwriting the published `replay_report.json`, copy the entire `v4.1` directory, including `results_100`, to a separate working directory; ensure the verified upstream decoders are present under its `original/` directory. Then run from that copied `v4.1` directory:

```bash
python3 replay_v4_1.py --output results_100
```

The replay checks the SHA-256 of `results_100/trace_replay.jsonl` against `results_100/manifest.json`, executes the original decoders for every retained trace, and compares the recovered output, errors, exact-recovery flag, and edit distance against retained records. The script writes `results_100/replay_report.json` in its working copy.

A fresh replay on a separate copy of a clean checkout, with the two original decoder scripts restored from the pinned upstream commit and verified by SHA-256, completed successfully:

- `trace_count`: 2,501
- `method_outputs_checked`: 7,503
- `expected_rows`: 7,503
- `failures`: 0
- `all_matched`: `true`
- process exit status: 0

This establishes repeatability of the recorded outputs with the original decoder implementations. It is not an independent validation of those decoders and does not reproduce timing acquisition on Intel TDX hardware.

## Generate a separate new campaign (optional)

Do **not** run this command against the retained published `results_100` directory. It creates a new RSA key and new observations; perturbation seeds do not make key generation deterministic.

```bash
python3 -m pip install cryptography
python3 run_v4.py --repeats 100 --window 64 --full-baseline --retain-traces --output results_new
```

Without `--retain-traces`, aggregate outputs can be generated but individual trace replay is unavailable.

## Data disclosure and interpretation

`trace_replay.jsonl` contains RSA-derived reference bits and synthetic observations that may disclose the private exponent of the throwaway experimental RSA key. The retained trace file is already included in the assessment repository. It must not be treated as secret material or reused as a production key. This disclosure and the absence of production-key use must be explicitly considered when distributing or reusing the dataset.

The manifest's signature verification and modular-arithmetic checks validate the original generated RSA key, not necessarily a recovered key. Exact recovery of the reconstructed exponent is the primary full-baseline check; a separate cryptographic operation with the reconstructed exponent remains an additional, unperformed validation. The event model is assumed, rather than derived from execution-derived RSA observations.
