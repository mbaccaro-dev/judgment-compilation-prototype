# Third-party notices

This repository separates project-authored material from retained source publications, source data, install-time dependencies, and compiled dependencies. Repository visibility does not change any of these terms.

## NIST Special Publication library

The retained library contains 195 NIST Special Publication 800-series PDFs and deterministic text projections made from them. Exact publication identities, NIST download pages, file hashes, and extraction details are recorded in `judgment_compilation/data/library/manifest.json`. NIST states that SP 800-series publications are not subject to copyright in the United States. NIST also warns that some NIST works may contain third-party material with separate rights. Original notices remain in the PDFs, and users must preserve applicable attribution and third-party notices. Inclusion does not imply NIST endorsement of this project or its interpretations.

Official references:

- https://www.nist.gov/itl/publications/nist-special-publication-800-series-general-information
- https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications

## NIST OSCAL and CPRT source data

The package retains checksum-bound NIST OSCAL and CPRT inputs. Exact roles, versions, source URLs, and hashes are recorded in `judgment_compilation/data/corpus/source/source_manifest.json`. The OSCAL license supplied by NIST is retained at `judgment_compilation/data/corpus/source/oscal-content-v1.5.0-LICENSE.md`; it describes the United States public-domain status, CC0 dedication, attribution request, no-endorsement boundary, and warranty limits for that source.

## PyMuPDF

PyMuPDF 1.28.0 is a declared install-time dependency and is not bundled in this repository. Its publisher offers PyMuPDF under GNU AGPL and commercial license terms. Installation and use must comply with the terms selected by the user. See https://pymupdf.readthedocs.io/en/latest/about.html#license-and-copyright.

## Rust executable dependencies

The Windows executable was built from the exact dependency versions in `rust/judgment_kernel/Cargo.lock`. Each dependency's package-declared license expression and exact license files from the resolved crate source are retained under `THIRD_PARTY_LICENSES/rust/`. `THIRD_PARTY_LICENSES/rust/index.json` maps every resolved crate version to those files. No dependency license applies to the project-authored code.
