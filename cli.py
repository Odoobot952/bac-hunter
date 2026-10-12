"""
bac-hunter CLI

Usage examples
--------------

Horizontal check (resource owned by userA, replayed as userB/userC):
    python -m bac_hunter horizontal \\
        --request requests/get_order.txt \\
        --owner sessions/userA.json \\
        --others sessions/userB.json sessions/userC.json

Vertical check (admin endpoint, replayed as a low-priv user):
    python -m bac_hunter vertical \\
        --request requests/admin_export.txt \\
        --low-priv sessions/userA.json sessions/userB.json

IDOR sweep (fuzz the ID in the path under one session):
    python -m bac_hunter idor \\
        --request requests/get_order.txt \\
        --persona sessions/userA.json \\
        --spread 10

Method/path tampering (bypass attempts against one persona):
    python -m bac_hunter tamper \\
        --request requests/delete_user.txt \\
        --persona sessions/userB.json

Every command writes a Markdown findings file to output/ for anything
flagged, pre-filled with a curl PoC.
"""

from __future__ import annotations
import argparse
import os
import sys
from datetime import datetime

from .request_parser import load_request_file
from .session_manager import load_persona
from .poc_generator import to_curl, finding_to_markdown
from .checks.horizontal import check_horizontal
from .checks.vertical import check_vertical
from .checks.idor import check_idor
from .checks.method_tamper import check_method_tamper

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except ImportError:
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()


def _print_flag(flagged: bool, line: str):
    color = Fore.RED if flagged else Fore.GREEN
    prefix = "[FLAGGED]" if flagged else "[ok]     "
    print(f"{color}{prefix}{Style.RESET_ALL} {line}")


def _write_findings(findings: list[str], out_dir: str, name: str) -> str | None:
    if not findings:
        return None
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(out_dir, f"{name}-{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# BAC Findings: {name}\n\n")
        f.write("\n---\n\n".join(findings))
    return path


def cmd_horizontal(args):
    req = load_request_file(args.request, base_url=args.base_url)
    owner = load_persona(args.owner)
    others = [load_persona(p) for p in args.others]

    results = check_horizontal(req, owner, others)
    findings = []
    for r in results:
        _print_flag(r.flagged, f"{r.owner_persona}'s resource via {r.tested_persona}: "
                                f"HTTP {r.status_code} -- {r.note}")
        if r.flagged:
            curl = to_curl(req.method, r.url, req.headers, req.body)
            findings.append(finding_to_markdown(
                title=f"Horizontal BAC: {owner.name}'s resource accessible as {r.tested_persona}",
                severity="High",
                description=f"Request originally captured for persona '{owner.name}' at "
                             f"{r.url} also succeeds when replayed with persona "
                             f"'{r.tested_persona}'s session, suggesting missing "
                             f"ownership checks (IDOR / horizontal privilege escalation).",
                curl_cmd=curl,
                status_code=r.status_code,
                response_snippet="(see live response -- re-run curl above)",
            ))

    out = _write_findings(findings, args.output, "horizontal")
    if out:
        print(f"\nFindings written to {out}")


def cmd_vertical(args):
    req = load_request_file(args.request, base_url=args.base_url)
    low_priv = [load_persona(p) for p in args.low_priv]

    results = check_vertical(req, low_priv)
    findings = []
    for r in results:
        _print_flag(r.flagged, f"{r.tested_persona} -> {r.url}: HTTP {r.status_code} -- {r.note}")
        if r.flagged:
            curl = to_curl(req.method, r.url, req.headers, req.body)
            findings.append(finding_to_markdown(
                title=f"Vertical BAC: privileged endpoint reachable as {r.tested_persona}",
                severity="Critical",
                description=f"{r.url} appears to require elevated privileges, but responds "
                             f"successfully when accessed with low-privilege persona "
                             f"'{r.tested_persona}', suggesting a missing function-level "
                             f"access control check.",
                curl_cmd=curl,
                status_code=r.status_code,
                response_snippet="(see live response -- re-run curl above)",
            ))

    out = _write_findings(findings, args.output, "vertical")
    if out:
        print(f"\nFindings written to {out}")


def cmd_idor(args):
    req = load_request_file(args.request, base_url=args.base_url)
    persona = load_persona(args.persona)

    results = check_idor(req, persona, id_spread=args.spread, max_requests=args.max_requests)
    findings = []
    for r in results:
        _print_flag(r.flagged, f"id={r.tried_value or 'n/a'} -> {r.url}: "
                                f"HTTP {r.status_code} -- {r.note}")
        if r.flagged:
            curl = to_curl(req.method, r.url, req.headers, req.body)
            findings.append(finding_to_markdown(
                title=f"Candidate IDOR at {r.url}",
                severity="Medium (confirm manually)",
                description=f"Substituting ID '{r.tried_value}' into the path responded as "
                             f"valid rather than denied under persona '{persona.name}'. "
                             f"Confirm the returned data actually belongs to a different "
                             f"owner before reporting.",
                curl_cmd=curl,
                status_code=r.status_code,
                response_snippet="(see live response -- re-run curl above)",
            ))

    out = _write_findings(findings, args.output, "idor")
    if out:
        print(f"\nFindings written to {out}")


def cmd_tamper(args):
    req = load_request_file(args.request, base_url=args.base_url)
    persona = load_persona(args.persona)

    results = check_method_tamper(req, persona)
    findings = []
    for r in results:
        _print_flag(r.flagged, f"{r.technique} -> {r.url}: HTTP {r.status_code} -- {r.note}")
        if r.flagged:
            curl = to_curl(req.method, r.url, req.headers, req.body)
            findings.append(finding_to_markdown(
                title=f"Access control bypass via {r.technique}",
                severity="High",
                description=f"The original request to {req.url} is denied for persona "
                             f"'{persona.name}', but the variant '{r.technique}' succeeds, "
                             f"suggesting the access control check is tied to the exact "
                             f"method/path rather than the underlying resource.",
                curl_cmd=curl,
                status_code=r.status_code,
                response_snippet="(see live response -- re-run curl above)",
            ))

    out = _write_findings(findings, args.output, "tamper")
    if out:
        print(f"\nFindings written to {out}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bac-hunter",
        description="OWASP A01 Broken Access Control tester -- authorized testing only.",
    )
    parser.add_argument("--output", default="output", help="Directory to write findings to")
    sub = parser.add_subparsers(dest="command", required=True)

    p_h = sub.add_parser("horizontal", help="Test cross-user access to the same resource type")
    p_h.add_argument("--request", required=True)
    p_h.add_argument("--owner", required=True, help="Persona the request was captured as")
    p_h.add_argument("--others", required=True, nargs="+", help="Personas to replay as")
    p_h.add_argument("--base-url")
    p_h.set_defaults(func=cmd_horizontal)

    p_v = sub.add_parser("vertical", help="Test low-priv access to a privileged endpoint")
    p_v.add_argument("--request", required=True)
    p_v.add_argument("--low-priv", required=True, nargs="+")
    p_v.add_argument("--base-url")
    p_v.set_defaults(func=cmd_vertical)

    p_i = sub.add_parser("idor", help="Fuzz a numeric ID in the request path")
    p_i.add_argument("--request", required=True)
    p_i.add_argument("--persona", required=True)
    p_i.add_argument("--spread", type=int, default=5)
    p_i.add_argument("--max-requests", type=int, default=10)
    p_i.add_argument("--base-url")
    p_i.set_defaults(func=cmd_idor)

    p_t = sub.add_parser("tamper", help="Try method/path/header bypasses against a persona")
    p_t.add_argument("--request", required=True)
    p_t.add_argument("--persona", required=True)
    p_t.add_argument("--base-url")
    p_t.set_defaults(func=cmd_tamper)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
