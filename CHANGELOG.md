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
- Reject shell syntax that can redirect I/O, expand to other paths, or unescape
  separators in `shell.exec` (`< > { } [ ] ( ) \\ ' "`); option flags such as
  `ls -la` are no longer mistaken for path arguments.
- Match the shell sensitive-path deny patterns on path segments rather than
  substrings, so files such as `setup.aws.md` are not over-blocked.
- Reject undeclared tool arguments (schema-strict, fail-closed).
- Block destructive filesystem operations whose path resolves to a parent of the
  allowlisted directory or to filesystem root, even when `approved=true`.

### Known limitations

- Path canonicalization is lexical and does not touch the filesystem: a symlink
  inside `/workspace` that points elsewhere is not detected. Tool executors must
  resolve paths (e.g. `realpath` + prefix check, or `O_NOFOLLOW`) at execution time.

### Added

- Corpus negatives for the policy/gate bypasses above, plus encoding, `//`,
  mixed-case, and absolute/relative variants.
- Shell syntax-abuse negatives (output redirection, brace expansion, backslash
  escapes).
- Benign ALLOW scenarios that exercise the new canonicalization and denylist
  rules (dot segments, mixed-case directories, `ls` flags, query strings, and
  file names containing `aws` / `credentials`), so over-blocking regressions
  are caught.
- Hypothesis property-based fuzz tests for the path canonicalizer.

### Changed

- Package version bumped to `0.2.0`.
- Evidence regenerated from a full corpus run (claims remain scoped **on this corpus**).

## [0.1.0] — 2026-10-16

### Added

- Initial fail-closed Agent Security Contract gate, demo policy, abuse-case corpus,
  evidence envelopes, and CI wiring.
