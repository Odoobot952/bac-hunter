"""
IDOR sweep: takes a request containing a numeric or UUID-style ID
(in the path or query string), and fuzzes nearby/alternate IDs under a
SINGLE persona's session to see which ones return data that looks valid
rather than a denial. You still need to eyeball the hits -- this flags
candidates, it doesn't itself prove the IDs belong to someone else.
"""

from __future__ import annotations
import re
import requests
from dataclasses import dataclass

from ..request_parser import ParsedRequest
from ..session_manager import Persona, apply_persona
from ..diff import fingerprint, looks_denied
from .horizontal import send

NUMERIC_ID = re.compile(r"(?<![\w])(\d{1,10})(?![\w])")
UUID_ID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


@dataclass
class IdorResult:
    tried_value: str
    url: str
    status_code: int
    flagged: bool
    note: str


def _candidate_numeric_ids(original: str, spread: int = 5) -> list[str]:
    n = int(original)
    candidates = set()
    for delta in range(-spread, spread + 1):
        if delta == 0:
            continue
        candidate = n + delta
        if candidate >= 0:
            candidates.add(str(candidate))
    return sorted(candidates, key=int)


def find_id_in_path(path: str) -> tuple[str, int, int] | None:
    """Returns (matched_text, start, end) for the first numeric or UUID-like
    ID found in the path, or None."""
    match = UUID_ID.search(path)
    if match:
        return match.group(0), match.start(), match.end()
    match = NUMERIC_ID.search(path)
    if match:
        return match.group(0), match.start(), match.end()
    return None


def check_idor(
    req: ParsedRequest,
    persona: Persona,
    id_spread: int = 5,
    max_requests: int = 10,
) -> list[IdorResult]:
    found = find_id_in_path(req.path)
    if not found:
        return [IdorResult(
            tried_value="",
            url=req.url,
            status_code=0,
            flagged=False,
            note="no numeric or UUID-style ID detected in path -- "
                 "point this check at an endpoint like /api/orders/123",
        )]

    original_value, start, end = found

    if UUID_ID.fullmatch(original_value):
        return [IdorResult(
            tried_value=original_value,
            url=req.url,
            status_code=0,
            flagged=False,
            note="UUID-style ID detected -- sequential fuzzing isn't meaningful here; "
                 "test by substituting IDs harvested from other requests/responses instead",
        )]

    candidates = _candidate_numeric_ids(original_value, spread=id_spread)[:max_requests]
    headers = apply_persona(req.headers, persona)
    results = []

    for candidate in candidates:
        new_path = req.path[:start] + candidate + req.path[end:]
        test_req = ParsedRequest(
            method=req.method,
            path=new_path,
            headers=req.headers,
            body=req.body,
            host=req.host,
            scheme=req.scheme,
        )
        try:
            resp = send(test_req, headers)
        except requests.RequestException as exc:
            results.append(IdorResult(
                tried_value=candidate,
                url=test_req.url,
                status_code=0,
                flagged=False,
                note=f"request error: {exc}",
            ))
            continue

        fp = fingerprint(resp.status_code, resp.text)
        denied = looks_denied(fp)

        results.append(IdorResult(
            tried_value=candidate,
            url=test_req.url,
            status_code=resp.status_code,
            flagged=not denied,
            note="RESPONDS AS VALID -- confirm whether this ID belongs to someone else"
                 if not denied else "denied / not found",
        ))

    return results
