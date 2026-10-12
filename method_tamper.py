"""
Method and path tampering: sometimes access control is enforced only for
one HTTP method, or only for an exact path string, and can be bypassed by:

  - Switching GET <-> POST <-> PUT <-> DELETE <-> OPTIONS
  - Adding a trailing slash, double slash, or path case change
  - Adding a fake extension (.json, .html) or override headers
  - Common bypass header tricks (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)

This check tries a fixed set of mutations against a single persona's
session and flags any that unexpectedly succeed where the original did not.
"""

from __future__ import annotations
import requests
from dataclasses import dataclass

from ..request_parser import ParsedRequest
from ..session_manager import Persona, apply_persona
from ..diff import fingerprint, looks_denied
from .horizontal import send

METHODS_TO_TRY = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]


@dataclass
class TamperResult:
    technique: str
    url: str
    status_code: int
    flagged: bool
    note: str


def _path_variants(path: str) -> list[tuple[str, str]]:
    variants = [
        ("trailing slash", path.rstrip("/") + "/"),
        ("double slash", path.replace("/", "//", 1)),
        ("trailing dot", path.rstrip("/") + "."),
        ("case change", path.swapcase()),
    ]
    # de-dupe against the original
    return [(label, p) for label, p in variants if p != path]


def check_method_tamper(
    req: ParsedRequest,
    persona: Persona,
    baseline_denied: bool = True,
) -> list[TamperResult]:
    """
    `req` should be a request you've already confirmed is denied for
    `persona` at its original method+path (e.g. a 403 on DELETE for a
    low-priv user). This tries variants to see if any of them bypass that.
    """
    results = []
    headers = apply_persona(req.headers, persona)

    for method in METHODS_TO_TRY:
        if method == req.method:
            continue
        test_req = ParsedRequest(method=method, path=req.path, headers=req.headers,
                                  body=req.body, host=req.host, scheme=req.scheme)
        try:
            resp = send(test_req, headers)
        except requests.RequestException as exc:
            results.append(TamperResult(f"method={method}", test_req.url, 0, False, str(exc)))
            continue
        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)
        results.append(TamperResult(
            technique=f"method={method}",
            url=test_req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="POSSIBLE BYPASS via method swap" if not denied else "denied",
        ))

    for label, new_path in _path_variants(req.path):
        test_req = ParsedRequest(method=req.method, path=new_path, headers=req.headers,
                                  body=req.body, host=req.host, scheme=req.scheme)
        try:
            resp = send(test_req, headers)
        except requests.RequestException as exc:
            results.append(TamperResult(label, test_req.url, 0, False, str(exc)))
            continue
        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)
        results.append(TamperResult(
            technique=label,
            url=test_req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="POSSIBLE BYPASS via path mutation" if not denied else "denied",
        ))

    for header_template in BYPASS_HEADERS:
        extra = {k: v.format(path=req.path) for k, v in header_template.items()}
        merged_headers = {**headers, **extra}
        try:
            resp = send(req, merged_headers)
        except requests.RequestException as exc:
            results.append(TamperResult(f"header={list(extra)[0]}", req.url, 0, False, str(exc)))
            continue
        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)
        results.append(TamperResult(
            technique=f"header={list(extra)[0]}",
            url=req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="POSSIBLE BYPASS via header trick" if not denied else "denied",
        ))

    return results
