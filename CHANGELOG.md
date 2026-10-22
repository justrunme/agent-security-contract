# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- External-auth quickstart (`examples/external-auth`): kind cluster with Envoy
  `ext_authz` calling the real ASC `/v1/evaluate` sidecar in front of an MCP
  demo server; integration corpus (allow / block / require-approval plus
  fail-closed authorizer-down, timeout, malformed, no-credentials); CI job;
  evidence in `docs/EVIDENCE-EXTERNAL-AUTH.md` scoped **on this corpus**.
- Optional `[test]` extras (`pytest`, `hypothesis`) for running the test suite.
- Unit tests for the ext_authz adapter helpers (payload normalize, status map,
  credentials, and `call_asc` fail-closed paths).

### Fixed

- External-auth evidence notes: envelopes are recorded for ASC/adapter
  BLOCK/REQUIRE_APPROVAL rows (not claimed for every row / wrong results path).
- Authorizer-down wording: adapter process stopped (nothing on :9191), not
  "scaled to zero".

## [0.2.1] — 2026-10-19

### Fixed

- Optional tool arguments: declared args may set `required: false` so an omitted
  optional argument PASSes while a present optional argument is still fully
  validated (type, pattern, hosts, length). Undeclared arguments still BLOCK.
  `required` defaults to `true` for backward compatibility with v0.2.0 policies.
- Policy load rejects a malformed per-argument `required` (must be a boolean)
  and any unknown argument-constraint key (e.g. a `deny_pattern` typo or an
  unsupported `default`), so a constraint can never be dropped silently.
- An argument that carries string constraints (`pattern`, `deny_patterns`,
  `allow_hosts`, `max_length`) now BLOCKs when its value is not a string, even
  if it is typed `any` (e.g. an explicit `null` for an optional argument).
- Destructive filesystem calls without a string `path` BLOCK even when the
  policy marks `path` optional and the call is approved.
- Evidence envelopes record the real head commit: prefer `ASC_COMMIT_SHA` over
  `GITHUB_SHA`, and CI/action set `ASC_COMMIT_SHA` from
  `github.event.pull_request.head.sha` (or `github.sha` on push) so PR runs no
  longer stamp the ephemeral merge ref.

### Added

- Demo `email.send` capability with optional `attachments`.
- Corpus scenarios for optional-arg PASS/BLOCK paths (omit, valid present,
  missing required, undeclared, invalid optional, wrong type).
- Unit tests covering optional omit, invalid optional, missing required,
  undeclared args, wrong types, and malformed `required` in policy YAML.

### Changed

- Package version bumped to `0.2.1`.
- Evidence regenerated from a full corpus run (claims remain scoped **on this corpus**).

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
