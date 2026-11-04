# Contributing to ZENOS

Thank you for helping. Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md);
reports go to hello@zenos-os.org. A few rules keep the project trustworthy:

1. **No unverified security claims.** If a change makes something "secure", add or update the row in
   [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and include a test that demonstrates it.
2. **English first.** Code, comments, UI text and docs are written in English; translations come after.
3. **Familiar UI.** Staff must be able to use ZENOS without training. Prefer the conventions people already know
   over new interaction patterns, and keep controls visible (no hover-only buttons).
4. **No single-vendor lock-in.** New dependencies need a reason, a license compatible with Apache-2.0 (or a clear
   note when they are not), and a look at the project's own stated limitations.
5. **Never commit secrets or personal data.** Use the files in `config/examples/` as templates and keep real values
   outside the repository.
6. **Design first.** UI changes start as a frame in the ZENOS Figma file; the code follows the frame.

## Your first contribution

If this is your first time contributing, here is what you need to know:

- **Where to start:** look for issues labeled [good first issue](https://github.com/zenos-org/zenos/labels/good%20first%20issue)
  — they are linked from the README, not from this file.
- **Pull requests:** every PR opens with a checklist in
  [.github/pull_request_template.md](.github/pull_request_template.md). It is fine to leave a box
  unticked if you have a reason; just explain it in the PR description.
- **Paths that need review:** changes to the paths listed in
  [.github/CODEOWNERS](.github/CODEOWNERS) require the maintainer's approval before they can be
  merged. Documentation changes are the quickest way to get started — this file is a good first target.
- **When to expect a reply:** pull requests, issues and comments are reviewed about five times a day, around
  22:30, 02:30, 06:30, 10:30 and 14:30 UTC, by the project's AI assistant. Merges of anything beyond documentation
  wait for the maintainer.
- **Claiming an issue:** say so in a comment on the issue. Once we confirm, the issue is yours for 24 hours; if no
  pull request has arrived by then, another contributor's pull request for the same issue may be reviewed instead.
  Issues without the good first issue or help wanted label may need a design or a maintainer decision first, so
  please ask before starting on one.

Before sending a change:

```
python3 -W error::ResourceWarning -m unittest discover -s tests
packaging/check-secrets.sh
```

### On Windows

The tests check Linux itself (the kernel's network filter and sandboxing, the TPM, Debian packages), so they run on
Linux, not on Windows. On Windows, use WSL 2, which runs Debian inside Windows (free, from Microsoft):

```
wsl --install -d Debian          # in PowerShell, once; restart if asked, then open "Debian"
sudo apt update
sudo apt install -y git python3 python3-cryptography curl zstd bubblewrap
git clone https://github.com/<your account>/zenos && cd zenos
python3 -m unittest discover -s tests
```

For changes under `formal/`, install Lean as the CI does (see `.github/workflows/test.yml`) and run `lake build`
in `formal/`. If you cannot run the tests at all, send the pull request anyway: CI runs every test on each pull
request (a maintainer approves the first run for a first-time contributor), and failures are explained there.

Changes to the root services (`system/sbin`) are tested on a clean Debian 13 install of the package, not only in
the development layout. See [docs/RELEASING.md](docs/RELEASING.md) for releases.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
