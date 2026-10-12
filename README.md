# bac-hunter

A small Python tool + methodology for finding **OWASP A01:2025 — Broken
Access Control** issues during authorized penetration testing and bug
bounty work: horizontal privilege escalation (IDOR), vertical privilege
escalation, missing function-level access control, and HTTP method/path
based bypasses.

Every flagged finding is written to `output/` as a Markdown file with a
ready-to-run `curl` PoC attached, so findings are report-ready by default.

> **Authorized testing only.** Only run this against systems you own or
> have explicit written permission to test (your own lab, CTF platforms,
> or in-scope bug bounty programs). Misusing this against systems you
> don't have permission to test is illegal.

## Install

```bash
git clone https://github.com/Odoobot952/bac-hunter.git
cd bac-hunter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Project layout

```
bac-hunter/
├── bac_hunter/            # the tool
│   ├── cli.py             # entrypoint — four subcommands, see below
│   ├── request_parser.py  # parses raw HTTP request files (Burp exports)
│   ├── session_manager.py # loads persona/session JSON files
│   ├── diff.py            # "does this look denied?" heuristics
│   ├── poc_generator.py   # curl + Markdown PoC generation
│   └── checks/
│       ├── horizontal.py      # cross-user access to the same resource
│       ├── vertical.py        # low-priv access to admin endpoints
│       ├── idor.py            # numeric/UUID ID fuzzing
│       └── method_tamper.py   # method/path/header bypass attempts
├── methodology/
│   ├── A01_checklist.md   # full BAC test-case checklist
│   ├── burp_workflow.md   # how to pair this with Burp/Autorize
│   └── report_template.md # PoC-first report template
├── sessions/*.example.json   # persona templates (copy, fill in, don't commit)
├── requests/*.example.txt    # raw request templates
└── output/                   # generated findings land here (gitignored)
```

## Setup per engagement

1. Capture a request in Burp (right-click → "Copy as raw request") for
   each scenario you want to test, save it under `requests/`.
2. Create a session file per persona under `sessions/` (copy an
   `*.example.json`, fill in real cookies/tokens, **don't commit it** —
   see `.gitignore`).

## Usage

**Horizontal check** — does userA's resource leak to userB/userC?
```bash
python -m bac_hunter horizontal \
  --request requests/get_order.txt \
  --owner sessions/userA.json \
  --others sessions/userB.json sessions/userC.json
```

**Vertical check** — does an admin endpoint respond to a low-priv session?
```bash
python -m bac_hunter vertical \
  --request requests/admin_export.txt \
  --low-priv sessions/userA.json sessions/userB.json
```

**IDOR sweep** — fuzz the numeric ID in the request path:
```bash
python -m bac_hunter idor \
  --request requests/get_order.txt \
  --persona sessions/userA.json \
  --spread 10
```

**Method/path tampering** — try bypasses on an endpoint that denies
the base request:
```bash
python -m bac_hunter tamper \
  --request requests/delete_user.txt \
  --persona sessions/userB.json
```

Any flagged result is written to `output/<check>-<timestamp>.md` with a
curl command you can paste straight into a report (see
`methodology/report_template.md`).

## Notes on the "denied" heuristic

`diff.py` treats a response as "denied" if it returns 401/403/404/405, or
if the body contains common deny phrases ("access denied", "forbidden",
etc.). This is intentionally simple and will have false positives/negatives
on apps with custom error pages — always confirm a flagged finding
manually before reporting it (see `methodology/A01_checklist.md` and
`methodology/report_template.md`).

## Roadmap ideas
- JWT role-claim tampering check (decode, modify `role`/`isAdmin`, re-sign
  with common weak secrets, replay)
- Mass-assignment fuzzing on update endpoints (inject `role`, `isAdmin`,
  `plan` fields not present in the original body)
- Burp extension wrapper so this can run as a passive/active scan check
  instead of a standalone CLI
