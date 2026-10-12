# A01:2025 Broken Access Control — Test Case Checklist

Scope note: as of OWASP Top 10 2025, SSRF has been merged into this
category. Test SSRF-adjacent access-control cases (internal metadata
endpoints, server-side fetch-by-URL features) alongside the items below.

## 1. Horizontal privilege escalation (IDOR)
- [ ] Identify every endpoint that takes a resource ID (path, query, or body)
- [ ] For each, capture a request as User A, replay as User B with the same ID
- [ ] Try the ID as: an integer increment/decrement, a UUID from another
      account, a base64/hashed value decoded and re-encoded
- [ ] Check both read (GET) and write (PUT/PATCH/DELETE) paths — write-path
      IDOR is usually rated higher severity
- [ ] Check nested/related resources (e.g. `/orders/{id}/items`, not just
      `/orders/{id}`)

## 2. Vertical privilege escalation
- [ ] Map all admin/staff-only endpoints (check JS bundles, API schemas,
      robots.txt, sitemap, and directory brute-force for hints)
- [ ] Replay each with a standard user session
- [ ] Replay each with an unauthenticated session (no cookie/token at all)
- [ ] Check role-switch via client-controlled values (JWT `role` claim,
      hidden form field, `X-Role` header, request body `isAdmin`)

## 3. Missing function-level access control
- [ ] For every UI action gated by role (e.g. a "Delete user" button), hit
      the underlying API directly with a lower-priv session, bypassing the
      UI entirely
- [ ] Check that disabling/hiding a button client-side isn't the only control

## 4. HTTP method / path based bypass
- [ ] Try alternate verbs on a protected route (GET allowed, is DELETE?)
- [ ] Try path variations: trailing slash, double slash, case change,
      URL-encoded traversal (`%2e%2e/`), fake extensions (`.json`)
- [ ] Try bypass headers: `X-Original-URL`, `X-Rewrite-URL`,
      `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization`

## 5. Mass assignment leading to privilege escalation
- [ ] On profile/account update endpoints, add extra fields not shown in
      the UI (`role`, `isAdmin`, `plan`, `permissions`) and see if the
      server accepts them

## 6. CORS and cross-origin access control
- [ ] Check `Access-Control-Allow-Origin` reflects arbitrary origins
      combined with `Access-Control-Allow-Credentials: true`

## 7. SSRF via access-control gaps (now under A01:2025)
- [ ] Any "fetch URL / import from link / webhook" feature: try internal
      IPs, `169.254.169.254` (cloud metadata), alternate schemes
      (`file://`, `gopher://`)

## 8. JWT / token-based access control
- [ ] Check `alg: none` acceptance
- [ ] Check if role/privilege claims can be modified without invalidating
      the signature (weak secret, key confusion `RS256` -> `HS256`)
- [ ] Check token reuse after logout/role downgrade (is it actually
      invalidated server-side?)

## Reporting discipline (per past rejections — PoC or it didn't happen)
- Every finding needs a working curl/PoC that a triager can run as-is
- State the exact impact: whose data, what action, what privilege gained
- Avoid "configuration" language without a working exploit attached —
  informational-only reports get triaged down
