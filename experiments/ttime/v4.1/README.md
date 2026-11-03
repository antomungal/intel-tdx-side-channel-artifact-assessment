# T-Time v4.1 — auditable RSA-derived synthetic experiments

Author: Antonio Muñoz - NICS Lab - UMA

## Scientific scope

This is **synthetic** encoding of bits of a valid RSA-2048 private exponent, **not** an execution-derived timing trace, Intel TDX leakage, or a demonstrated hardware RSA attack. Original third-party T-Time scripts in `original/` are unchanged.

## Run 100 repetitions per condition

```bash
python3 -m pip install cryptography
python3 run_v4.py --repeats 100 --window 64 --full-baseline --retain-traces --output results_100
python3 replay_v4_1.py --output results_100
```

Expected: 25 conditions × 100 repetitions × 3 methods + 3 full-baseline method outputs = **7503** trial-method rows; 2501 retained trace pairs (2500 windows plus one full baseline), 78 summary rows, and 7503 replay checks. The full baseline is one key and one trace, not 100 trials.

**Sensitive:** `--retain-traces` writes the original bitstrings and synthetic observations; both can reveal the RSA private exponent. Keep `results_100` private, do not publish or share it unchanged, and do not use a production RSA key. The generated key is a throwaway experiment key. The traces permit replay of the original decoders, but the cryptographic key-generation event is not deterministic and is not reproduced from a seed.

Without `--retain-traces`, aggregate outputs are generated but individual trace replay is unavailable. Preserve `manifest.json`, `trials.csv`, `summary.csv`, `baseline_replay.json`, and `replay_report.json`. `replay_v4_1.py` checks all retained traces and method outputs. Original scripts are third-party and not assigned the authorship header.

## Important limitations

The two oracle methods use privileged generator labels and are not deployable attacks. The decoder's event model is assumed rather than derived from a real RSA implementation. The manifest's signature verification and modular arithmetic check validate the original key, not necessarily a recovered key. An exact match of the reconstructed exponent is the primary full-baseline check. A separate reconstructed-exponent cryptographic operation remains a recommended follow-up.
