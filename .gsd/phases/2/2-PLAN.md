---
phase: 2
plan: 2
wave: 1
---

# Plan 2.2: Client UI Error Boundaries & Graceful Degradation

## Objective
Update the web UI to handle upstream API failures, network dropouts, and malformed manual IOC submissions gracefully through inline error toasts and loading state recovery.

## Context
- .gsd/SPEC.md
- index.html
- js/app.js
- js/engine/cti-manager.js

## Tasks

<task type="auto">
  <name>Build Toast Notification System</name>
  <files>
    index.html
    css/index.css
    js/app.js
  </files>
  <action>
    - Ensure `#error-toast` or similar notification container exists in `index.html` (add if missing).
    - Add CSS classes for sliding toast animations, error colors, and auto-dismissal.
    - Implement a `showError(message)` function in `app.js` that appends and clears messages.
  </action>
  <verify>grep -A 10 "function showError" js/app.js</verify>
  <done>Toast notification function is available globally for the UI.</done>
</task>

<task type="auto">
  <name>Wire Up API Failures to UI Toasts</name>
  <files>
    js/app.js
    js/engine/cti-manager.js
  </files>
  <action>
    - Within the `analyzeLiveIOCs` and `lookupIOC` workflow in `app.js`, catch `Promise` rejections and server-provided error arrays.
    - If `results.errors` has contents, call `showError` with user-friendly descriptions (e.g., "VirusTotal API timed out").
    - Ensure loading spinners are immediately removed on failure instead of leaving the UI indefinitely frozen. Disable the Analyze button during loading.
  </action>
  <verify>grep -A 5 "catch" js/app.js</verify>
  <done>Catch blocks explicitly hook into the toast notification system and reset button states.</done>
</task>

## Success Criteria
- [ ] Network failures during live analysis display a visible error message to the user.
- [ ] The "Analyze" button re-enables properly even if the request throws an exception.
- [ ] Failed feeds (e.g., OTX timed out) still render partial data from successful feeds without throwing fatal JS errors.
