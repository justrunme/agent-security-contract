"""Unit and property-based tests for path canonicalization."""

from __future__ import annotations

import posixpath

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from asc.paths import (
    PathCanonicalizeError,
    canonicalize_path,
    is_sensitive_path,
    is_under_prefix,
    resolves_to_parent_or_root,
)


def test_canonicalize_resolves_parent() -> None:
    assert canonicalize_path("/workspace/..") == "/"
    assert canonicalize_path("/workspace/out/..") == "/workspace"
    assert canonicalize_path("/workspace/foo/../bar") == "/workspace/bar"


def test_canonicalize_percent_decode_repeated() -> None:
    assert canonicalize_path("/workspace/..%2fetc/passwd") == "/etc/passwd"
    assert canonicalize_path("/workspace/%252e%252e%252fetc/passwd") == "/etc/passwd"


def test_canonicalize_collapses_duplicate_slashes() -> None:
    assert canonicalize_path("/workspace//out///a") == "/workspace/out/a"
    assert canonicalize_path("//etc/shadow") == "/etc/shadow"


def test_canonicalize_rejects_nul() -> None:
    with pytest.raises(PathCanonicalizeError, match="NUL"):
        canonicalize_path("/workspace/foo\x00/bar")
    with pytest.raises(PathCanonicalizeError, match="NUL"):
        canonicalize_path("/workspace/%00passwd")


def test_canonicalize_expands_tilde() -> None:
    assert canonicalize_path("~/.ssh/id_rsa") == "/root/.ssh/id_rsa"
    assert canonicalize_path("~alice/.aws/credentials") == "/home/alice/.aws/credentials"


def test_canonicalize_idempotent_examples() -> None:
    samples = [
        "/workspace/README.md",
        "/workspace/out/../out/a.txt",
        "/workspace/%2e%2e/etc/passwd",
        "relative/../path",
    ]
    for sample in samples:
        once = canonicalize_path(sample)
        assert canonicalize_path(once) == once


def test_sensitive_paths() -> None:
    assert is_sensitive_path("/root/.aws/credentials")
    assert is_sensitive_path("/etc/shadow")
    assert is_sensitive_path("/Etc/Shadow")
    assert is_sensitive_path("/proc/self/environ")
    assert is_sensitive_path("/proc/123/environ")
    assert is_sensitive_path("~/.ssh/id_rsa")
    assert is_sensitive_path("/home/bob/.kube/config")
    assert not is_sensitive_path("/workspace/README.md")
    assert not is_sensitive_path("/workspace/out/notes.txt")


def test_parent_or_root_detection() -> None:
    assert resolves_to_parent_or_root("/", "/workspace/out/")
    assert resolves_to_parent_or_root("/workspace", "/workspace/out/")
    assert resolves_to_parent_or_root("/workspace/out", "/workspace/out/")
    assert not resolves_to_parent_or_root("/workspace/out/tmp.txt", "/workspace/out/")


def test_is_under_prefix() -> None:
    assert is_under_prefix("/workspace", "/workspace")
    assert is_under_prefix("/workspace/a", "/workspace")
    assert not is_under_prefix("/tmp", "/workspace")
    assert not is_under_prefix("/workspace-other", "/workspace")


# --- Property-based fuzz ---

# Printable path alphabet without NUL; include % for encoding fuzz.
_PATH_CHARS = st.sampled_from(
    list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-%~")
)


@given(st.text(alphabet=_PATH_CHARS, min_size=1, max_size=64))
@settings(max_examples=200)
def test_fuzz_canonicalize_no_nul_in_output(value: str) -> None:
    try:
        out = canonicalize_path(value)
    except PathCanonicalizeError:
        return
    assert "\x00" not in out


@given(st.text(alphabet=_PATH_CHARS, min_size=1, max_size=64))
@settings(max_examples=200)
def test_fuzz_canonicalize_idempotent(value: str) -> None:
    try:
        once = canonicalize_path(value)
        twice = canonicalize_path(once)
    except PathCanonicalizeError:
        return
    assert once == twice


@given(st.text(alphabet=_PATH_CHARS, min_size=1, max_size=64))
@settings(max_examples=200)
def test_fuzz_canonicalize_no_dotdot_segment(value: str) -> None:
    """After canonicalize, no remaining '..' path segment (except a relative leading ..)."""
    try:
        out = canonicalize_path(value)
    except PathCanonicalizeError:
        return
    parts = out.split("/")
    # Absolute paths must not contain '..'; relative may only keep leading '..' chains
    # that normpath could not resolve without a root.
    if out.startswith("/"):
        assert ".." not in parts
    else:
        # Strip a single leading relative-escape prefix, then no further '..'.
        while parts and parts[0] == "..":
            parts = parts[1:]
        assert ".." not in parts


@given(
    st.lists(
        st.sampled_from(["workspace", "out", "docs", "a", "b", ".", "..", "", "%2e", "%2e%2e"]),
        min_size=1,
        max_size=8,
    )
)
@settings(max_examples=150)
def test_fuzz_joined_segments_match_normpath_after_decode(segments: list[str]) -> None:
    raw = "/" + "/".join(segments)
    try:
        out = canonicalize_path(raw)
    except PathCanonicalizeError:
        return
    # Re-normalizing the output with posixpath must be a no-op.
    assert posixpath.normpath(out) == out


@given(st.binary(min_size=1, max_size=32))
@settings(max_examples=100)
def test_fuzz_reject_embedded_nul_bytes(data: bytes) -> None:
    if b"\x00" not in data:
        return
    text = data.decode("latin-1")
    with pytest.raises(PathCanonicalizeError):
        canonicalize_path(text)
