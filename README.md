# Judgment Compilation

A local prototype for browsing 195 included NIST publications and running source-linked checks. Results include the source passages, supplied facts, missing facts, and calculation steps.

The package reads its included document collection. It has no PDF upload feature.

## Run

Requires Python 3.11 or later and PyMuPDF 1.28.0.

```powershell
python -m pip install .
jc status
jc demo
jc documents --limit 200
jc reviewed-programs
jc verify
jc serve --port 0
```

The web page runs on the local computer. `Ctrl+C` stops it.

## Architecture

- **Source records:** 195 NIST publications, 15,478 PDF pages, extracted text, page locations, and SHA-256 hashes.
- **Data contracts:** typed records for Domain, Judgment, Work, and Architecture.
- **Compilation:** reviewed records are validated, linked, and compiled into programs.
- **Verification:** file hashes, review records, source links, required inputs, and conflicting inputs are checked.
- **Runtime:** 64-bit Windows uses the included Rust engine. Linux and macOS use the Python engine.
- **Interfaces:** the command line and local web page use the same application services and JSON records.

## Review status

**Fully reviewed documents: 0 of 195.**

**Documents with reviewed checks: 9.**

| Publication | Reviewed check |
| --- | --- |
| NIST SP 800-53 Rev. 5 Update 1 | Five source links and three compiled checks |
| NIST SP 800-100 Update 1 | Page 39 awareness and training prerequisite facts |
| NIST SP 800-101 Rev. 1 | Mobile-device recovery activity |
| NIST SP 800-108 Rev. 1 Update 1 | Counter-mode capacity guard |
| NIST SP 800-111 | Centralized-management applicability |
| NIST SP 800-145 | Section 2 cloud characteristics supplied by the caller |
| NIST SP 800-150 | TLP Table 3-3 classification lookup |
| NIST SP 800-30 Rev. 1 | Table G-5 overall-likelihood lookup |
| NIST SP 800-37 Rev. 2 | Prepare step P-1 role-assignment entry |

The SP 800-53 index also contains 2,138 structured statement and item templates.

## Limits

- Search returns source text and citations.
- Compiled checks are available for the publications listed above.
- Input validation covers required fields, value formats, and source links.
- People remain responsible for applicability, responsibility, compliance, and action decisions.
- The package performs no external actions.
- The included native executable supports 64-bit Windows. Linux and macOS use the Python engine.

## License

See [LICENSE.md](LICENSE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
