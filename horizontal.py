"""
Horizontal BAC check: does a request meant for one user's data also
succeed when replayed with a *different* user's session, at the same
privilege level?

Typical target: /api/users/{id}/profile, /api/orders/{id}, /messages/{id}
-- anything scoped to "the current user" by an ID rather than by the
session itself.
"""

from __future__ import annotations
import requests
from dataclasses import dataclass

from ..request_parser import ParsedRequest
from ..session_manager import Persona, apply_persona
from ..diff import fingerprint, looks_denied


@dataclass
class HorizontalResult:
    owner_persona: str
    tested_persona: str
    url: str
    status_code: int
    flagged: bool
    note: str


def send(req: ParsedRequest, headers: dict, timeout: int = 15) -> requests.Response:
    return requests.request(
        req.method,
        req.url,
        headers=headers,
        data=req.body or None,
        timeout=timeout,
        allow_redirects=False,
        verify=True,
    )


def check_horizontal(
    req: ParsedRequest,
    owner: Persona,
    other_personas: list[Persona],
) -> list[HorizontalResult]:
    """
    `req` should be captured while authenticated as `owner`, pointing at a
    resource that belongs to `owner` (e.g. owner's own order ID).
    We then replay the exact same request, swapping in each of
    `other_personas`'s auth material, and see if it still succeeds.
    """
    results = []

    for persona in other_personas:
        headers = apply_persona(req.headers, persona)
        try:
            resp = send(req, headers)
        except requests.RequestException as exc:
            results.append(HorizontalResult(
                owner_persona=owner.name,
                tested_persona=persona.name,
                url=req.url,
                status_code=0,
                flagged=False,
                note=f"request error: {exc}",
            ))
            continue

        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)

        results.append(HorizontalResult(
            owner_persona=owner.name,
            tested_persona=persona.name,
            url=req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="POSSIBLE HORIZONTAL BAC: resource accessible cross-user"
                 if not denied else "access correctly denied",
        ))

    return results
