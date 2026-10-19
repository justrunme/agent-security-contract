# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-10-19

### Security

- Canonicalize path arguments before allowlist checks: repeated percent-decode,
  NUL rejection, slash collapse, and `..` resolution via POSIX `normpath`.
- Treat `shell.exec` as deny-by-default: only `ls` / `cat` / `echo`, confine path
  arguments under `/workspace`, and apply a sensitive-path denylist to every
  string argument (credentials, `/etc/shadow`, `/proc/*/environ`, `.aws`, `.ssh`,
  `.kube`, and related locations).
- Reject undeclared tool arguments (schema-strict, fail-closed).
- Block destructive filesystem operations whose path resolves to a parent of the
  allowlisted directory or to filesystem root, even when `approved=true`.

### Added

- Corpus negatives for the policy/gate bypasses above, plus encoding, `//`,
  mixed-case, and absolute/relative variants.
- Balancing benign ALLOW scenarios so ALLOW count remains ≥ attack count on this
  corpus.
- Hypothesis property-based fuzz tests for the path canonicalizer.

### Changed

- Package version bumped to `0.2.0`.
- Evidence regenerated from a full corpus run (claims remain scoped **on this corpus**).

## [0.1.0] — 2026-10-19

### Added

- Initial fail-closed Agent Security Contract gate, demo policy, abuse-case corpus,
  evidence envelopes, and CI wiring.
