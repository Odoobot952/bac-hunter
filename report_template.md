# Vulnerability Report Template (PoC-first)

Past submissions without a working proof-of-concept were triaged as
informational and rejected. This template puts the PoC near the top,
not buried after a long description.

---

## Title
`[Broken Access Control] <specific impact> on <endpoint>`
e.g. `[Broken Access Control] Horizontal IDOR allows reading any user's
order history via /api/orders/{id}`

## Severity
CVSS-informed estimate + your own impact statement (e.g. "High — allows
any authenticated user to read PII of any other user").

## Summary (2-3 sentences)
What's broken, who's affected, what an attacker gains.

## Steps to Reproduce
1. Authenticate as [role/account].
2. Send the following request (replace tokens as needed):

```bash
curl -i -X GET 'https://target.example.com/api/orders/1042' \
  -H 'Cookie: session=<LOW_PRIV_SESSION>'
```

3. Observe: HTTP 200 with another user's order data returned, despite
   the session belonging to a different account.

## Proof of Concept
- Attach the exact curl command(s) used (bac-hunter writes these
  automatically into `output/*.md` for every flagged finding)
- Attach a screenshot or response body snippet showing the leaked/
  modified data, with sensitive values redacted

## Impact
Be concrete: "An attacker can enumerate order IDs sequentially and
retrieve the name, address, and order history of every user on the
platform," not just "access control issue."

## Suggested Fix
Server-side ownership check: verify the resource's owner_id matches the
authenticated session's user_id before returning/modifying data, rather
than relying on the ID being hard to guess.

## Affected URL(s)
List every confirmed-affected endpoint, not just the first one found.
