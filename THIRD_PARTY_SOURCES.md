# Third-party source provenance

This document records the provenance of external implementations
referenced by the experimental assessments.

Original third-party implementations are not redistributed in this
repository unless explicitly identified.

## T-Time

Original repository:
https://github.com/koreacsl/T-Time

Verified upstream commit:
a0db080725e79339bcacbefd8fea4b6abdfcd352

Verified files:

1. attack/T-Time_poc_host/poc/evaluation_mbedtls/parse/restore/pattern_second.py

   SHA-256:
   01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223

2. attack/T-Time_poc_host/poc/evaluation_mbedtls/parse/restore/pattern_third.py

   SHA-256:
   98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4

Both files were compared byte-for-byte, through SHA-256, against
their contents in the identified upstream Git commit.

The local upstream checkout contains modifications to unrelated
kernel files. The two verified scripts match the committed versions.

Licensing:
No project-wide license covering these scripts has been established.
Licenses found in third-party subdirectories and the kernel tree
must not be assumed to cover the T-Time scripts.

Redistribution:
The original scripts are not included in this repository.

Assessment:
The retained T-Time results concern offline processing and synthetic
traces. They do not constitute reproduction of the original attack
on Intel TDX hardware.

## TDXdown

Original repository:
https://github.com/UzL-ITS/tdxdown

Repository revision inspected:
8aaa34f3da0d8d93637c66ca8e34aef3b7c45f76

Official artifact deposit:
https://doi.org/10.5281/zenodo.12683611

Verification date: 2026-11-03.

The upstream README identifies the Zenodo deposit as the
distribution source for the submitted experimental artifacts.

The following local archives were compared against the
file sizes and MD5 checksums published by Zenodo:

1. tdxdown-paper-artifacts.zip

   Size: 585841679 bytes
   MD5: 8c17b1a94754b266c2ff1055e3a4eb7f
   Result: MATCH

2. cryptanalysis.zip

   Size: 80368072 bytes
   MD5: 96b0dd0057891906d562aeb0ae90c4c4
   Result: MATCH

Both local archives match the corresponding files in the
official Zenodo record.

The GitHub revision inspected contains documentation rather
than the experimental source files. Consequently, the local
experimental source is attributed to the verified Zenodo
distribution, not to a matching Git source-tree revision.

Licensing:
The GitHub repository contains a GNU GPL version 3 license.
Its applicability to individual components of the separately
distributed Zenodo archives, including bundled third-party
dependencies, has not been independently established.

Redistribution:
Neither original ZIP archive is redistributed in this
assessment repository.

The cryptanalysis archive must not be added to this
repository because it contains private-key material.

Assessment:
The assessment includes retained offline verification reports
and locally developed verification procedures.

See experiments/tdxdown/PREFIX_RECONCILIATION.md for the
documented difference between the original nonce-prefix
predicate and the preserved audit report.

The archive checksums establish correspondence with the
published distribution. They do not establish successful
reproduction of the original attack on Intel TDX hardware.

## TDXploit

Original repository:
https://github.com/isec-tugraz/TDXploit

Verified upstream commit:
f7c9fdf64d9786c3b94a6f34cf0c9375f546a0ad

Verification date: 2026-11-03.

The local README.md and ten selected source files were compared
byte-for-byte using SHA-256 against the identified upstream commit.

Verified source files:

- Section3/singlestepping/attacker_td/int.c
- Section3/singlestepping/host/int.c
- Section3/singlestepping/host/int.h
- Section3/singlestepping/victim_td/int.c
- Section3/openssl/modified-kernel-modules/host/int.c
- Section3/openssl/modified-kernel-modules/host/int.h
- Section3/openssl/single-stepping-attack.patch
- Section3/openssl/tdx_step_userland/src/bin/apic_attack/main.rs
- Section3/openssl/tdx_step_userland/src/graz_step.rs
- Section3/openssl/tdx_step_userland/src/freq_sneak.rs

Verification results:

- README.md: MATCH.
- Selected source files: 10 MATCH.
- Differences or retrieval errors: 0.

The assessment also retains event-selection and signature-provenance
records, together with locally developed verification procedures.

The source comparison establishes byte-level identity only for
the listed files. It does not establish identity of the complete
source tree or provenance of all experimental traces.

Licensing:
A project-wide license covering the verified TDXploit components
has not been established. Licenses associated with the included
Linux kernel or other third-party dependencies must not be assumed
to cover the TDXploit implementation.

Redistribution:
The original third-party source code is not included in this
assessment repository.

Assessment:
The retained verification results do not constitute reproduction
of the original attack on Intel TDX hardware.

## Attribution and limitations

A matching source hash establishes content identity with the
specified Git revision. It does not establish licensing rights,
independent implementation, or successful reproduction of the
original attack.

Verification scripts developed for this assessment must be
distinguished from original third-party implementations.
