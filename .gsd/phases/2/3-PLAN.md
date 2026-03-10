---
phase: 2
plan: 3
wave: 2
---

# Plan 2.3: Simulation Parameter Validation & Execution Tests

## Objective
Harden the game theory and reinforcement learning simulation configurations so that malformed hyperparameter inputs do not crash the engine, and verify the backend proxy protections with automated tests.

## Context
- .gsd/SPEC.md
- js/engine/rl-agent.js
- index.html
- js/app.js
- tests/server.test.mjs

## Tasks

<task type="auto">
  <name>Harden Simulation Configuration Parsing</name>
  <files>
    index.html
    js/engine/rl-agent.js
    js/app.js
  </files>
  <action>
    - Add strict HTML validation constraints (`min`, `max`, `step`) to the parameter inputs (Alpha, Gamma, Epsilon) in `index.html`.
    - Apply fallback clamping in `app.js` config setup: ensure `alpha` is between `[0, 1]`, `gamma` `[0, 1]`, and episodes are `> 0`.
    - If `NaN` is detected from input parsing, force fallback to acceptable defaults instead of pushing `NaN` to the game state.
  </action>
  <verify>grep -E "Math.min|Math.max|parseFloat" js/app.js</verify>
  <done>Malicious or accidental garbage values in the parameter inputs cannot corrupt the RL Q-table.</done>
</task>

<task type="auto">
  <name>Extend Server Tests for Edge Cases</name>
  <files>tests/server.test.mjs</files>
  <action>
    - Write a test ensuring `POST /api/cti/lookup` returns `400 Bad Request` if `ioc` string length > 256.
    - Write a basic test confirming that multiple rapid requests get blocked by the `express-rate-limit` middleware (Status `429 Too Many Requests`).
    - Run the entire test suite via `npm test` continuously passing.
  </action>
  <verify>node --test tests/server.test.mjs</verify>
  <done>Server proxy integration tests assert timeouts and 429 status codes.</done>
</task>

## Success Criteria
- [ ] Passing string parameters or `0` for episodes does not break simulation metrics.
- [ ] Express server native testing validates abuse limits natively.
