"""
Vertical BAC check: does an admin/privileged-only endpoint also respond
successfully to a lower-privileged session?

Typical target: /admin/users, /api/admin/export, /internal/*, any endpoint
that should require an elevated role.
"""

from __future__ import annotations
import requests
from dataclasses import dataclass

from ..request_parser import ParsedRequest
from ..session_manager import Persona, apply_persona
from ..diff import fingerprint, looks_denied
from .horizontal import send


@dataclass
class VerticalResult:
    tested_persona: str
    url: str
    status_code: int
    flagged: bool
    note: str


def check_vertical(
    req: ParsedRequest,
    low_priv_personas: list[Persona],
) -> list[VerticalResult]:
    """
    `req` should be captured while authenticated as a HIGH-privilege
    persona (e.g. admin), hitting a privileged endpoint. We replay it
    with each low-privilege persona's auth material.
    """
    results = []

    for persona in low_priv_personas:
        headers = apply_persona(req.headers, persona)
        try:
            resp = send(req, headers)
        except requests.RequestException as exc:
            results.append(VerticalResult(
                tested_persona=persona.name,
                url=req.url,
                status_code=0,
                flagged=False,
                note=f"request error: {exc}",
            ))
            continue

        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)

        results.append(VerticalResult(
            tested_persona=persona.name,
            url=req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="POSSIBLE VERTICAL BAC: privileged endpoint reachable by low-priv role"
                 if not denied else "access correctly denied",
        ))

    return results
