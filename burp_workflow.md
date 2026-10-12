# Burp Suite Workflow for BAC Testing

## Setup
1. Create one Burp project per target, with separate browser profiles
   (or separate Firefox containers) logged in as each test persona
   (admin, userA, userB, unauthenticated).
2. Use the **Autorize** extension (BApp Store) as the first pass:
   - Configure it with the low-privilege session's cookie/header
   - Browse the app as the HIGH-privilege user with Burp as proxy
   - Autorize automatically replays each request with the low-priv session
     and flags ones that return a similar response (possible bypass)
3. Export anything Autorize flags as "Bypassed" or "Is Enforced?" unclear
   into individual raw request files for manual confirmation.

## Manual confirmation pass
For each candidate from Autorize (or from this project's `bac-hunter`
CLI), confirm manually in Burp Repeater:
1. Send the original request as the intended persona — confirm it works.
2. Send it again swapping in the other persona's session — note the
   actual status code and whether the response body contains the
   expected (or someone else's) data, not just a 200.
3. Try the write-path equivalent if the finding is on a GET (does the
   same missing check apply to PUT/DELETE on the same resource?).

## Useful Burp extensions for this category
- **Autorize** — automated access-control diffing (core tool for this)
- **AuthMatrix** — define a role matrix and test many endpoints x many
  roles in one pass, good for larger apps with 3+ roles
- **Turbo Intruder** — scripted IDOR sweeps at higher speed than Intruder
  when you need to fuzz thousands of IDs

## Handoff to bac-hunter CLI
Once you've identified a request pattern worth automating (e.g. a
resource type with many instances to sweep), export it from Burp as
"Copy as raw request" into `requests/<name>.txt` and run it through the
CLI's `idor` or `horizontal` command for a quick first pass across many
IDs, generating PoC curl commands automatically for any hits.
