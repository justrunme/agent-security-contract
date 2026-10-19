"""Path canonicalization and sensitive-path checks for fail-closed gating."""

from __future__ import annotations

import posixpath
import re
from urllib.parse import unquote

# Bound repeated percent-decoding so pathological inputs cannot loop forever.
_MAX_DECODE_ROUNDS = 64

# Absolute / home-relative / dot-relative tokens that may appear in shell args.
_PATH_TOKEN_RE = re.compile(
    r"(?P<path>~[^ \t\n;&|`$]*|/(?:[^ \t\n;&|`$]*)|\.\.?(?:/[^ \t\n;&|`$]*)+)"
)

# Case-insensitive sensitive locations. Checked against canonicalized forms.
_SENSITIVE_PATH_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(^|/)\.aws(/|$)"),
    re.compile(r"(?i)(^|/)\.ssh(/|$)"),
    re.compile(r"(?i)(^|/)\.kube(/|$)"),
    re.compile(r"(?i)(^|/)credentials$"),
    re.compile(r"(?i)/etc/shadow$"),
    re.compile(r"(?i)/etc/gshadow$"),
    re.compile(r"(?i)/etc/passwd$"),
    re.compile(r"(?i)/etc/sudoers"),
    re.compile(r"(?i)/proc/self/environ$"),
    re.compile(r"(?i)/proc/[^/]+/environ$"),
    re.compile(r"(?i)^/root(/|$)"),
    re.compile(r"(?i)/home/[^/]+/\.ssh(/|$)"),
    re.compile(r"(?i)/home/[^/]+/\.aws(/|$)"),
    re.compile(r"(?i)/home/[^/]+/\.kube(/|$)"),
)


class PathCanonicalizeError(ValueError):
    """Raised when a path cannot be safely canonicalized (fail closed)."""


def canonicalize_path(value: str) -> str:
    """Percent-decode repeatedly, reject NUL, collapse slashes, resolve ``..``.

    Returns a POSIX-normalized path string. Does not touch the filesystem
    (no symlink follow). Relative inputs stay relative after ``normpath``.
    """
    if not isinstance(value, str):
        raise PathCanonicalizeError("path must be a string")
    if "\x00" in value:
        raise PathCanonicalizeError("NUL byte in path")

    decoded = value
    for _ in range(_MAX_DECODE_ROUNDS):
        if "\x00" in decoded:
            raise PathCanonicalizeError("NUL byte in path")
        try:
            nxt = unquote(decoded, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PathCanonicalizeError(f"invalid percent-encoding: {exc}") from exc
        if nxt == decoded:
            break
        decoded = nxt
    else:
        raise PathCanonicalizeError("percent-decoding did not converge")

    if "\x00" in decoded:
        raise PathCanonicalizeError("NUL byte in path")

    # Expand ~ and ~user to absolute forms for consistent denylist / prefix checks.
    if decoded == "~" or decoded.startswith("~/"):
        decoded = "/root" + decoded[1:]
    elif decoded.startswith("~"):
        # ~other → /home/other/...
        rest = decoded[1:]
        if "/" in rest:
            user, _, tail = rest.partition("/")
            decoded = f"/home/{user}/{tail}" if tail else f"/home/{user}"
        else:
            decoded = f"/home/{rest}"

    # Collapse symlink-like duplicate slashes (including leading //).
    while "//" in decoded:
        decoded = decoded.replace("//", "/")

    normalized = posixpath.normpath(decoded)
    # posixpath.normpath("") == "."; treat empty as invalid for gate use.
    if normalized == "":
        raise PathCanonicalizeError("empty path after canonicalization")
    return normalized


def is_sensitive_path(value: str) -> bool:
    """Return True if value (after canonicalize) matches the sensitive denylist."""
    try:
        canonical = canonicalize_path(value)
    except PathCanonicalizeError:
        return True
    for pattern in _SENSITIVE_PATH_RES:
        if pattern.search(canonical):
            return True
    # Also scan the lower-cased canonical string for credential filenames.
    lower = canonical.lower()
    if lower.endswith("/credentials") or lower.endswith(".pem") or lower.endswith(".key"):
        return True
    return False


def is_under_prefix(canonical: str, prefix: str) -> bool:
    """True if canonical equals prefix (no trailing slash) or is strictly under it."""
    root = prefix.rstrip("/")
    if not root:
        return False
    return canonical == root or canonical.startswith(root + "/")


def resolves_to_parent_or_root(canonical: str, allowed_prefix: str) -> bool:
    """True if canonical is ``/`` or a parent of the allowlisted directory prefix.

    Destructive tools must BLOCK these even when ``approved=true``.
    """
    if canonical in {"/", ".", ""}:
        return True
    root = allowed_prefix.rstrip("/")
    if not root or root == "/":
        return canonical == "/"
    # Ancestors of the allowlisted directory (e.g. /workspace for /workspace/out).
    if root.startswith(canonical.rstrip("/") + "/") and canonical != root:
        return True
    # The allowlisted directory itself is not a file *under* the prefix.
    if canonical == root:
        return True
    return False


def extract_path_tokens(text: str) -> list[str]:
    """Extract path-like tokens from a free-form string (e.g. shell command)."""
    return [m.group("path") for m in _PATH_TOKEN_RE.finditer(text)]


def prefix_from_pattern(pattern: str | None) -> str | None:
    """Derive a directory prefix from an anchored pattern like ``^/workspace/out/``."""
    if not pattern:
        return None
    match = re.match(r"^\^(/[\w./-]+/)", pattern)
    if match:
        return match.group(1)
    return None
