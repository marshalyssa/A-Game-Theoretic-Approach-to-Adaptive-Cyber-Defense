---
phase: 1
plan: 1
wave: 1
---

# Plan 1.1: Test Framework Setup + Bayesian & Game Engine Tests

## Objective
Set up Node.js native test runner (`node:test`) and write unit tests for the two core mathematical engines: `bayesian-engine.js` and `game-engine.js`. These modules contain the mathematical foundation of the thesis and must be verified for correctness.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- js/engine/bayesian-engine.js
- js/engine/game-engine.js
- js/data/mitre-catalog.js
- js/data/attacker-profiles.js
- js/data/defender-actions.js

## Tasks

<task type="auto">
  <name>Create test infrastructure</name>
  <files>
    - tests/setup.js (NEW)
    - package.json (MODIFY — add test script)
  </files>
  <action>
    1. Create a `tests/` directory at project root
    2. Create `tests/setup.js` that re-exports data modules for test reuse
       - Must handle ES module imports (the engine files use `export` syntax)
       - Use `--experimental-vm-modules` flag if needed, or convert test files to .mjs
    3. Update `package.json`:
       - Change `"test"` script to: `"node --experimental-vm-modules --test tests/**/*.test.mjs"`
       - Ensure `"type": "commonjs"` remains unchanged (server.js needs it)
    4. Do NOT install any test framework — use Node.js built-in `node:test` and `node:assert`
  </action>
  <verify>npm test runs and exits (even if no tests yet)</verify>
  <done>Running `npm test` executes without "no test specified" error</done>
</task>

<task type="auto">
  <name>Unit test bayesian-engine.js</name>
  <files>tests/bayesian-engine.test.mjs (NEW)</files>
  <action>
    Test the following properties:
    1. `createBeliefState()` — returns uniform [0.25, 0.25, 0.25, 0.25] by default
    2. `createBeliefState(prior)` — normalizes custom prior correctly
    3. `updateBelief()` — posterior shifts toward correct type after observing a type-specific technique
    4. `updateBelief()` — multiple updates converge belief (entropy decreases monotonically)
    5. `updateBeliefBatch()` — equivalent to sequential single updates
    6. `decayBelief()` — decayed belief moves toward uniform; with rate=0 returns original
    7. `getBeliefEntropy()` — uniform distribution gives max entropy ≈ 2.0; certain distribution gives 0
    8. `getMostProbableType()` — returns correct type and probability
    9. `predictNextTechnique()` — returns normalized distribution (sums to ~1.0)
    10. `getTopPredictions()` — returns N items sorted by probability descending
  </action>
  <verify>npm test — all bayesian-engine tests pass</verify>
  <done>≥10 test cases pass for bayesian-engine with zero failures</done>
</task>

<task type="auto">
  <name>Unit test game-engine.js</name>
  <files>tests/game-engine.test.mjs (NEW)</files>
  <action>
    Test the following properties:
    1. `computeDefenderUtility()` — returns numeric value; higher for effective actions against matching tactic
    2. `computeDefenderUtility()` — "Do Nothing" has zero cost/disruption
    3. `computeAttackerUtility()` — returns numeric value; higher when defense is weak
    4. `computePayoffMatrix()` — returns correct dimensions (techniques × actions)
    5. `computePayoffMatrix()` — defender and attacker matrices have same dimensions
    6. `bestDefenderResponse()` — returns action with highest expected utility
    7. `solveMixedStrategy()` — returns valid probability distributions (sum to 1, all ≥ 0)
    8. `rankDefenderActions()` — returns actions sorted by expected utility descending
    9. `rankDefenderActions()` — each action has name, expectedUtility, cost, disruption fields
    10. `expectedUtility()` — weighted sum computed correctly for known input
  </action>
  <verify>npm test — all game-engine tests pass</verify>
  <done>≥10 test cases pass for game-engine with zero failures</done>
</task>

## Success Criteria
- [ ] `npm test` runs using Node.js native test runner
- [ ] ≥10 bayesian-engine tests pass
- [ ] ≥10 game-engine tests pass
- [ ] Zero test failures
- [ ] No external test framework dependencies added
