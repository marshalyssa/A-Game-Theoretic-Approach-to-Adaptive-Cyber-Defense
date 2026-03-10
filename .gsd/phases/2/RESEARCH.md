# Phase 2 Research: Edge Case Hardening

## Overview
Phase 2 focuses on handling malformed inputs, API failures, and boundary conditions gracefully. The major technical areas are external API stability (timeouts/rate limiting) and user experience (error boundary states).

## 1. Rate Limiting (Server)
To prevent abuse of our proxy endpoints, we need rate limiting.
- **Decision:** Use `express-rate-limit`. It's the standard for Express apps, zero dependencies, and extremely lightweight.
- **Implementation:** Install via `npm install express-rate-limit`, configure a global limiter (e.g., 100 requests per 15 minutes) or endpoint-specific limiters on `/api/cti/*`.

## 2. API Timeouts (Server)
The `node-fetch` package and standard Node.js native `fetch` both support `AbortController`.
- **Implementation:** Instead of letting requests hang indefinitely if VT/OTX/AbuseIPDB are slow, we will wrap calls with `AbortSignal.timeout(ms)`.
- **Threshold:** Set to 8000ms (8 seconds) to allow moderate processing time before failing fast.

## 3. Input Validation (Server/Client)
- Currently `detectIOCType` correctly maps formats, but the server proxy blindly accepts `req.body.ioc`.
- **Decision:** Add strict length and valid character validation on the server side to prevent absurdly huge payload attacks.

## 4. UI Error Boundaries
- **Decision:** Add toast notifications (or inline alerts) in `index.html` for both the Simulation UI and Live Analysis UI. If an API request throws or times out, the `app.js` UI controllers need to gracefully drop the loading state and show the error, rather than becoming unresponsive.

## Summary
Level 1 Discovery completed. The chosen patterns (`express-rate-limit`, `AbortController`, simple DOM manipulation for Toast UI) perfectly match the project's vanilla stack and require minimal new dependencies.
