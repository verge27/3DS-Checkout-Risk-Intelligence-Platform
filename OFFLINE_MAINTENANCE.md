# Offline report maintenance — local candidate only

Baseline: `bc3fd021327ef9faeae1f399413acf2f10a1d8ff` from
https://github.com/verge27/3DS-Checkout-Risk-Intelligence-Platform.git.

The repository's reporting pipelines and API wrappers include placeholders.
No complete offline exporter existed to repair, so this change adds a standalone
privacy-minimising exporter without importing or modifying scanner code.

## Scope

`offline_reports.py` reads existing local JSON arrays or JSON Lines. It retains
only a row number, validated timestamp, numeric duration and an error-presence
indicator. It drops target identities, payment information, secrets, free-text
errors, screenshots, network logs, bypass findings, enrichment and risk scores.
It does not perform regex-based "best effort" redaction: all unapproved fields
are omitted. The original report is unchanged and can still contain secrets.

Missing observations remain unknown. An empty error field is not evidence that
a scan succeeded, and the export makes no payment-security or compliance verdict.
Do not combine this metadata with scanner findings to claim validation.

## Run without installing scanner dependencies

Requires Python 3.11 or later, standard library only. Run from this checkout:

```sh
python -I offline_reports.py existing-report.json --output metadata.json
python -I offline_reports.py existing-report.jsonl --input-format jsonl --format csv --output metadata.csv
python -m unittest discover -s tests_offline -v
```

By default input is bounded to 8 MiB and 10,000 records. Explicit CLI limits are
validated and cannot exceed 64 MiB / 100,000 records. Malformed records, duplicate
JSON keys and non-finite numbers fail rather than being skipped. Output is fully
validated before writing. Existing output paths are never replaced; an I/O error
can leave a partial newly-created file, which is reported as failure.

Files are created with mode 0600 on platforms enforcing POSIX modes; Windows ACLs
follow the destination directory. Use a directory you control. Do not assume this
tool changes access controls on existing reports or guarantees their erasure.

## Deliberately unchanged

Checkout automation, browser profiles, scanning, network enrichment, payment-form
interaction, scoring and runtime dependency installation remain untouched. This is
not an end-to-end scanner repair or certification. No merchant sites are contacted.
No production deployment, commit or push is included.

The existing LICENSE file is truncated (it contains `...`); its provenance must be
resolved with the owner before a release. This change neither fills it in nor
asserts that GitHub's licence detection establishes a valid licence grant.
