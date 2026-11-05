# ZENOS roadmap

What comes next, in order. No dates are promised: an item ships when its tests and proofs pass. Each item has an
issue; the issues in the [0.1.3 milestone](https://github.com/zenos-org/zenos/milestone/1) and the
[Next milestone](https://github.com/zenos-org/zenos/milestone/2) show what is open and what is done. What has
already changed is in the [changelog](CHANGELOG.md).

## 0.1.3: the next release

- **Release what is in the source.** (#26) The key service (file keys off the PC), the PC's identity key in the TPM,
  the update-path checks (release ledger, update-folder watch, hourly integrity check) and the conductor's first
  version are in `main` but not in a release yet.
- **Office files, measured.** (#27) A compatibility check on public Word, Excel and PowerPoint files from Japanese
  ministries and municipalities runs in CI (`tests/office`), and its results are published, failures included.
- **Office files with their layout.** (#28) Today the ZENOS document and spreadsheet apps keep the text, values and
  formulas of an Office file, not its layout (tables, merged cells, borders, vertical writing, ruby, print areas,
  charts). Office files are to open in a full office engine running under ZENOS's rules (no macros, no network,
  sealed-file and printing rules), measured by the check above.
- **Contributing from Windows.** (#29) How to run the tests in WSL 2 ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Flaky heartbeat test** (#14).

## Next

- **Hardware keys.** (#30) Officers' keys on FIDO2 devices; confirmation on the phone for each file opened above one's
  level.
- **Mandatory access control.** (#31) SELinux multi-level security, so no program can write a copy of an open sealed
  file to a lower level.
- **A reproducible installer image.** (#32) Two builds of the ISO from the same source give the same file, as the
  `.deb` already does.
- **File integrity enforced.** (#33) IMA appraisal: files that were not released are refused at run time, not only
  reported.
- **The conductor, continued.** (#34) Multi-step plans; acts that cannot be taken back (sending, deleting, paying)
  with confirmation on the phone; API keys and the conductor's record sealed by the key service.
- **Everyday apps.** (#35) Files, Settings and notifications in the ZENOS style.

## Before any claim of production readiness

- **An external security audit**, published with its findings. (#36)

## Editions

Editions are configurations of one shared core: ZENOS Office first (Government is its strictest setting), then
Family and Personal. Later: Academy, Creator, Educational, Hobby.
