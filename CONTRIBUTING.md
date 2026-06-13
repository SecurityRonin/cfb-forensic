# Contributing to cfb-forensic

Thanks for your interest in improving `cfb-forensic`. This crate parses untrusted
Windows Shell Link (`.lnk`) files from potentially compromised systems, so
correctness and robustness are not negotiable. The bar is high and the workflow is
strict — please read this before opening a pull request.

## Test-Driven Development is mandatory

Every code change follows strict Red-Green-Refactor, and the RED and GREEN steps
land as **two separate commits**:

1. **RED** — write the failing test(s) first. They must define the expected
   behaviour and actually fail. Commit them alone. This commit is the verifiable
   proof that the test was written first.
2. **GREEN** — write the minimal implementation that makes the tests pass.
   Commit it separately.
3. **REFACTOR** — clean up while keeping every test green.

A single combined commit is not accepted. There is no "hard to test" exemption:
if something is awkward to unit test, use the closest testable abstraction,
fixtures, or an integration test — but write the test first.

Because you are validating code you wrote with tests you wrote, also validate
against **real data** where it matters: cross-check parsing against genuine `.lnk`
files (e.g. a Windows host's `%APPDATA%\Microsoft\Windows\Recent` folder), not
only the spec-exact synthetic fixtures. Never commit a real user's `.lnk` — it
embeds local paths, volume serials, the machine name, and droid GUIDs.

## Quality gates

All of the following must pass locally and in CI before a PR can merge:

```bash
cargo fmt --all -- --check                              # formatting
cargo clippy --workspace --all-targets -- -D warnings   # lints, warnings denied
cargo deny check                                        # license / advisory / source policy
cargo test --workspace                                  # unit + integration
cargo llvm-cov --workspace --lib --show-missing-lines   # 100% line coverage
```

- **Formatting** — `cargo fmt`; do not hand-format.
- **Lints** — `cargo clippy` with warnings denied.
- **Dependencies** — `cargo deny` must pass (no GPL, no flagged advisories).
- **Coverage** — 100% line coverage is enforced (except lines annotated
  `// cov:unreachable`). New code needs tests that exercise its error paths, not
  just the happy path.
- **Fuzzing** — changes to the reader must keep its fuzz target green. Run the
  relevant target before submitting:

  ```bash
  rustup install nightly
  cargo install cargo-fuzz
  cargo +nightly fuzz run shelllink     # or: forensic
  ```

  If the reader gains new structure handling, extend or add the matching fuzz
  target.

## Robustness expectations

- No panics on malicious input — every integer / length / offset read is
  bounds-checked; a truncated or garbled link yields absent sub-structures or
  `None`, never a crash. Use checked or saturating arithmetic.
- Fail loud where a real error is possible — surface it with enough context to
  diagnose. Never swallow an error or substitute a silently-wrong parse.
- Findings are **observations**, never verdicts — keep notes hedged ("consistent
  with …"); MITRE techniques narrate consistency, not conclusions.
- Keep `#![forbid(unsafe_code)]` intact.

## Commits and signing

- Keep diffs minimal — change only the lines the task requires; no drive-by
  reformatting of unrelated code.
- Commits are signed with [gitsign](https://github.com/sigstore/gitsign)
  (keyless Sigstore signing). Ensure your commits are signed before pushing.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting process.
