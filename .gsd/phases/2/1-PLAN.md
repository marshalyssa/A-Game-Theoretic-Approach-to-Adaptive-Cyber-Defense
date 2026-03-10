---
phase: 2
plan: 1
wave: 1
---

# Plan 2.1: Server Edge Case Hardening

## Objective
Harden the Express proxy server (`server.cjs`) against abuse, malformed input, and upstream API slowness by implementing rate limiting, input validation, and timeouts.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- .gsd/phases/2/RESEARCH.md
- js/engine/cti-manager.js

## Tasks

<task type="auto">
  <name>Install Rate Limiting Dependency</name>
  <files>package.json</files>
  <action>
    - Install `express-rate-limit` and add to project dependencies.
  </action>
  <verify>npm list express-rate-limit</verify>
  <done>Package resolves successfully in npm tree.</done>
</task>

<task type="auto">
  <name>Implement API Timeouts, Rate Limits, and Validation</name>
  <files>server.cjs</files>
  <action>
    - Require `express-rate-limit`.
    - Create a global rate limiter (e.g., 100 reqs / 15 mins) and apply it to `/api/cti/lookup` and other CTI endpoints.
    - Add strict input validation to `app.post('/api/cti/lookup', ...)` and individual endpoints (check string length < 256, handle missing fields gracefully with 400 statuses).
    - Add `AbortSignal.timeout(8000)` to the `fetch` options for OTX, VirusTotal, and AbuseIPDB calls.
    - Catch the `AbortError` or `TimeoutError` and map it to a user-friendly error message returned to the client.
  </action>
  <verify>node --test tests/server.test.mjs</verify>
  <done>Existing tests pass, and manually verified timeout or rate limiting behavior.</done>
</task>

## Success Criteria
- [ ] `express-rate-limit` acts as middleware preventing rapid-fire requests.
- [ ] Feeds that take longer than 8 seconds gracefully timeout instead of hanging the proxy.
- [ ] Extremely large or invalid payloads are blocked with a 400 Bad Request.
