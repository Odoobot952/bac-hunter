"""
Lightweight response comparison used to decide whether a response looks
like "access granted" vs "access denied", without needing a full diff
library. Deliberately simple and transparent -- tune the heuristics for
your target rather than trusting them blindly.
"""

from __future__ import annotations
from dataclasses import dataclass

DENY_STATUS = {401, 403, 404, 405}
DENY_KEYWORDS = (
    "access denied",
    "forbidden",
    "unauthorized",
    "not authorized",
    "permission denied",
    "you do not have",
    "login required",
)


@dataclass
class ResponseFingerprint:
    status_code: int
    length: int
    body_snippet: str


def fingerprint(status_code: int, body: str) -> ResponseFingerprint:
    return ResponseFingerprint(
        status_code=status_code,
        length=len(body or ""),
        body_snippet=(body or "")[:200].replace("\n", " "),
    )


def looks_denied(fp: ResponseFingerprint) -> bool:
    if fp.status_code in DENY_STATUS:
        return True
    lowered = fp.body_snippet.lower()
    return any(kw in lowered for kw in DENY_KEYWORDS)


def looks_like_bypass(baseline: ResponseFingerprint, test: ResponseFingerprint) -> bool:
    """
    baseline = response from a request we EXPECT to be denied
               (wrong user's session, lower-priv role, tampered method, etc.)
    test     = the same comparison point, used for context/logging

    Returns True when the "should be denied" response does NOT look denied,
    i.e. it looks like the access control check was bypassed.
    """
    return not looks_denied(baseline)


def length_delta_pct(a: ResponseFingerprint, b: ResponseFingerprint) -> float:
    if a.length == 0:
        return 100.0 if b.length else 0.0
    return abs(a.length - b.length) / a.length * 100
